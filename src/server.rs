//! HTTP serving with the connection-level limits `axum::serve` leaves out:
//! a request-header read timeout (slowloris), a write timeout (a client that
//! stops reading), a cap on open connections and on how long one connection
//! may live, plus graceful shutdown that drains in-flight requests.
//!
//! Only HTTP/1 is served. Detecting HTTP/2 means waiting for the first bytes
//! with no timer running, so a client that sent nothing held a connection
//! slot forever; every edge in front of the judge talks HTTP/1.1 to it.
use axum::{Router, extract::ConnectInfo};
use hyper::{body::Incoming, server::conn::http1};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener,
    sync::{Semaphore, watch},
    time::Sleep,
};
use tower::ServiceExt;

/// Read buffer per connection, so unfinished headers cannot pile up
/// hyper's default of about 400 KB each.
const MAX_BUF_SIZE: usize = 64 * 1024;

pub struct Limits {
    /// A client must send the complete request headers within this time,
    /// counted from the start of the connection and of each keep-alive wait.
    pub header_read_timeout: Duration,
    /// Open connections (including idle keep-alive ones) at once; further
    /// clients wait in the listen backlog.
    pub max_connections: usize,
    /// A write that makes no progress for this long closes the connection:
    /// a client that stops reading its responses (pipelining requests to fill
    /// the socket) would otherwise hold its slot with no timer running.
    pub write_timeout: Duration,
    /// A connection takes no new request after this time, and is dropped
    /// `shutdown_grace` later if it is still busy: the last backstop against
    /// a client that reads, but only a byte at a time.
    pub max_connection_age: Duration,
    /// How long a closing connection, at shutdown or past its age limit, may
    /// take to finish the request in flight.
    pub shutdown_grace: Duration,
}

pub async fn serve(
    listener: TcpListener,
    app: Router,
    limits: Limits,
    shutdown: impl Future<Output = ()>,
) {
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_read_timeout)
        .max_buf_size(MAX_BUF_SIZE);
    let connections = Arc::new(Semaphore::new(limits.max_connections));
    // Turns true at shutdown: every connection then finishes its request.
    let (closing, _) = watch::channel(false);
    let cut = Arc::new(AtomicUsize::new(0));
    tokio::pin!(shutdown);

    loop {
        let permit = tokio::select! {
            permit = connections.clone().acquire_owned() => {
                permit.expect("the connection semaphore is never closed")
            }
            () = &mut shutdown => break,
        };
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(conn) => conn,
                Err(e) => {
                    accept_error(e).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        stream.set_nodelay(true).ok();
        let app = app.clone();
        let service = hyper::service::service_fn(move |mut req: hyper::Request<Incoming>| {
            req.extensions_mut().insert(ConnectInfo(peer));
            app.clone().oneshot(req)
        });
        let io = TokioIo::new(WriteTimeout::new(stream, limits.write_timeout));
        let conn = builder.serve_connection(io, service);
        let mut closing = closing.subscribe();
        let cut = cut.clone();
        let (max_age, grace) = (limits.max_connection_age, limits.shutdown_grace);
        tokio::spawn(async move {
            let _permit = permit;
            tokio::pin!(conn);
            let done = tokio::select! {
                done = conn.as_mut() => Some(done),
                () = tokio::time::sleep(max_age) => None,
                _ = closing.wait_for(|closing| *closing) => None,
            };
            // At the age limit and at shutdown the request in flight is
            // answered and no further one is taken: dropping the connection
            // outright would fail a request a reverse proxy had just sent
            // over it. One that is still busy after the grace is dropped.
            let done = match done {
                Some(done) => Some(done),
                None => {
                    conn.as_mut().graceful_shutdown();
                    tokio::time::timeout(grace, conn.as_mut()).await.ok()
                }
            };
            match done {
                Some(Ok(())) => {}
                Some(Err(e)) => tracing::debug!(%peer, "connection closed with error: {e}"),
                None => {
                    cut.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(%peer, "connection dropped while still busy");
                }
            }
        });
    }

    drop(listener);
    cut.store(0, Ordering::Relaxed);
    closing.send_replace(true);
    // Every connection holds a permit until it ends, which takes the grace
    // at most; the outer limit only guards against a task that never does.
    let all = u32::try_from(limits.max_connections).unwrap_or(u32::MAX);
    let drained =
        tokio::time::timeout(limits.shutdown_grace * 2, connections.acquire_many(all)).await;
    let cut = cut.load(Ordering::Relaxed);
    if drained.is_err() || cut > 0 {
        tracing::warn!("graceful shutdown timed out; dropped {cut} busy connections");
    }
}

/// A stream whose writes fail with `TimedOut` after making no progress for
/// `timeout`. hyper stops its header timer once a request is parsed, so a
/// response the client never reads would otherwise wait forever.
struct WriteTimeout<T> {
    inner: T,
    timeout: Duration,
    stalled: Option<Pin<Box<Sleep>>>,
}

impl<T> WriteTimeout<T> {
    fn new(inner: T, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            stalled: None,
        }
    }

    /// Runs a write step; while it stays pending, the stall timer runs.
    fn progress<R>(
        &mut self,
        cx: &mut Context<'_>,
        step: impl FnOnce(&mut T, &mut Context<'_>) -> Poll<io::Result<R>>,
    ) -> Poll<io::Result<R>> {
        match step(&mut self.inner, cx) {
            Poll::Ready(r) => {
                self.stalled = None;
                Poll::Ready(r)
            }
            Poll::Pending => {
                let timeout = self.timeout;
                let timer = self
                    .stalled
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(timeout)));
                if timer.as_mut().poll(cx).is_ready() {
                    self.stalled = None;
                    return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
                }
                Poll::Pending
            }
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for WriteTimeout<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for WriteTimeout<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .progress(cx, |io, cx| Pin::new(io).poll_write(cx, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .progress(cx, |io, cx| Pin::new(io).poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Per-connection failures are routine; anything else (e.g. too many open
/// files) is logged and backed off so the loop does not spin.
async fn accept_error(e: io::Error) {
    if matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    ) {
        return;
    }
    tracing::error!("accept error: {e}");
    tokio::time::sleep(Duration::from_secs(1)).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use std::net::SocketAddr;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
        sync::oneshot,
        task::JoinHandle,
    };

    async fn start(
        header_read_timeout: Duration,
    ) -> (SocketAddr, oneshot::Sender<()>, JoinHandle<()>) {
        start_with(Limits {
            header_read_timeout,
            max_connections: 16,
            write_timeout: Duration::from_secs(30),
            max_connection_age: Duration::from_secs(60),
            shutdown_grace: Duration::from_secs(1),
        })
        .await
    }

    async fn start_with(limits: Limits) -> (SocketAddr, oneshot::Sender<()>, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app =
            Router::new()
                .route(
                    "/peer",
                    get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move {
                        peer.ip().to_string()
                    }),
                )
                .route(
                    "/slow",
                    get(|| async {
                        tokio::time::sleep(Duration::from_millis(600)).await;
                        "done"
                    }),
                )
                // Larger than the socket buffers on both ends, so a client that
                // does not read makes the server's write stall.
                .route("/big", get(|| async { vec![b'x'; 64 << 20] }));
        let (stop, stopped) = oneshot::channel::<()>();
        let handle = tokio::spawn(serve(listener, app, limits, async {
            stopped.await.ok();
        }));
        (addr, stop, handle)
    }

    #[tokio::test]
    async fn serves_requests_with_connect_info() {
        let (addr, stop, handle) = start(Duration::from_secs(5)).await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET /peer HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut resp = String::new();
        s.read_to_string(&mut resp).await.unwrap();
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert!(resp.ends_with("127.0.0.1"), "{resp}");
        stop.send(()).unwrap();
        handle.await.unwrap();
    }

    /// How long the server keeps a connection open after `payload`, or None
    /// when it is still open after 5 seconds.
    async fn time_to_close(addr: SocketAddr, payload: &[u8]) -> Option<Duration> {
        let mut s = TcpStream::connect(addr).await.unwrap();
        let started = tokio::time::Instant::now();
        s.write_all(payload).await.unwrap();
        let mut buf = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf))
            .await
            .ok()
            .map(|_| started.elapsed())
    }

    #[tokio::test]
    async fn slow_headers_are_cut_off() {
        let (addr, stop, handle) = start(Duration::from_millis(300)).await;
        // A client that sends nothing, an HTTP/2 preface that stops, and
        // headers that never finish are all closed by the header timer,
        // not earlier and not never.
        for payload in [
            &b""[..],
            &b"PRI * HT"[..],
            &b"GET /peer HTTP/1.1\r\nHost: x\r\n"[..],
        ] {
            let closed = time_to_close(addr, payload).await;
            let label = String::from_utf8_lossy(payload);
            let took = closed.unwrap_or_else(|| panic!("{label:?}: still open"));
            assert!(
                took >= Duration::from_millis(250),
                "{label:?}: closed after {took:?}"
            );
        }
        stop.send(()).unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn idle_keep_alive_is_cut_off() {
        let (addr, stop, handle) = start(Duration::from_millis(300)).await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET /peer HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 512];
        let n = s.read(&mut buf).await.unwrap();
        assert!(buf[..n].starts_with(b"HTTP/1.1 200"));
        // Keep-alive, then silence: the next request head is due in time too.
        let mut rest = Vec::new();
        let closed = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut rest)).await;
        assert!(closed.is_ok(), "idle keep-alive connection still open");
        stop.send(()).unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn a_stalled_write_times_out() {
        // The peer end of a 64-byte pipe is never read: the write stalls.
        let (ours, _theirs) = tokio::io::duplex(64);
        let mut io = WriteTimeout::new(ours, Duration::from_millis(200));
        let started = tokio::time::Instant::now();
        let err = tokio::time::timeout(Duration::from_secs(5), io.write_all(&[0u8; 4096]))
            .await
            .expect("the write never timed out")
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() >= Duration::from_millis(150));
    }

    #[tokio::test]
    async fn a_response_nobody_reads_ends_the_connection() {
        // hyper stops its header timer once a request is parsed; the write
        // timeout must still end a connection whose answer is never read.
        // (A pipe, not TCP: Windows loopback buffers megabytes.)
        let (server_end, mut client) = tokio::io::duplex(4096);
        client
            .write_all(
                b"GET /big HTTP/1.1
Host: x

",
            )
            .await
            .unwrap();
        let app = Router::new().route("/big", get(|| async { vec![b'x'; 1 << 20] }));
        let service = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
            app.clone().oneshot(req)
        });
        let io = TokioIo::new(WriteTimeout::new(server_end, Duration::from_millis(200)));
        let conn = http1::Builder::new()
            .timer(TokioTimer::new())
            .serve_connection(io, service);
        let ended = tokio::time::timeout(Duration::from_secs(5), conn)
            .await
            .expect("the connection outlived its stalled write");
        assert!(ended.is_err(), "the stalled write was not reported");
        drop(client);
    }

    #[tokio::test]
    async fn connections_are_capped_and_aged_out() {
        let (addr, stop, handle) = start_with(Limits {
            header_read_timeout: Duration::from_secs(30),
            max_connections: 1,
            write_timeout: Duration::from_secs(30),
            max_connection_age: Duration::from_millis(400),
            shutdown_grace: Duration::from_secs(1),
        })
        .await;
        // The first client holds the only slot by sending nothing.
        let _first = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        // The second is not served until the first ages out.
        let started = tokio::time::Instant::now();
        let mut second = TcpStream::connect(addr).await.unwrap();
        second
            .write_all(b"GET /peer HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut resp = String::new();
        tokio::time::timeout(Duration::from_secs(5), second.read_to_string(&mut resp))
            .await
            .expect("second client never served")
            .unwrap();
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert!(
            started.elapsed() >= Duration::from_millis(250),
            "served while the slot was taken"
        );
        stop.send(()).unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn a_request_in_flight_at_the_age_limit_is_answered() {
        let (addr, stop, handle) = start_with(Limits {
            header_read_timeout: Duration::from_secs(30),
            max_connections: 4,
            write_timeout: Duration::from_secs(30),
            max_connection_age: Duration::from_millis(200),
            shutdown_grace: Duration::from_secs(5),
        })
        .await;
        // A keep-alive request that outlives the connection's age limit.
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET /slow HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut resp = String::new();
        // The answer comes whole, then the connection closes by itself.
        tokio::time::timeout(Duration::from_secs(5), s.read_to_string(&mut resp))
            .await
            .expect("the connection was not closed after the answer")
            .unwrap();
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp:?}");
        assert!(resp.ends_with("done"), "{resp:?}");
        stop.send(()).unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_answers_the_request_in_flight() {
        let (addr, stop, handle) = start(Duration::from_secs(5)).await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET /slow HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        stop.send(()).unwrap();
        let mut resp = String::new();
        s.read_to_string(&mut resp).await.unwrap();
        assert!(resp.ends_with("done"), "{resp:?}");
        handle.await.unwrap();
    }
}
