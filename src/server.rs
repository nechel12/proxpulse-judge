//! HTTP-сервер с ограничениями уровня соединения, которых нет в `axum::serve`:
//! таймаут чтения заголовков запроса (slowloris) и лимит открытых соединений,
//! плюс корректное завершение с дренажом активных запросов.
use axum::{Router, extract::ConnectInfo};
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::{conn::auto::Builder, graceful::GracefulShutdown},
};
use std::{future::Future, io, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Semaphore};
use tower::ServiceExt;

pub struct Limits {
    /// Клиент должен отправить все заголовки запроса за это время.
    pub header_read_timeout: Duration,
    /// Одновременно открытых соединений (включая простаивающие keep-alive); остальные
    /// клиенты ждут в очереди прослушивания.
    pub max_connections: usize,
    /// Сколько времени завершение ждёт активные запросы.
    pub shutdown_grace: Duration,
}

pub async fn serve(
    listener: TcpListener,
    app: Router,
    limits: Limits,
    shutdown: impl Future<Output = ()>,
) {
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_read_timeout);
    builder.http2().timer(TokioTimer::new());
    let connections = Arc::new(Semaphore::new(limits.max_connections));
    let graceful = GracefulShutdown::new();
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
        let conn = graceful.watch(
            builder
                .serve_connection(TokioIo::new(stream), service)
                .into_owned(),
        );
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(%peer, "connection closed with error: {e}");
            }
            drop(permit);
        });
    }

    drop(listener);
    if tokio::time::timeout(limits.shutdown_grace, graceful.shutdown())
        .await
        .is_err()
    {
        tracing::warn!("graceful shutdown timed out; dropping remaining connections");
    }
}

/// Сбои отдельных соединений обычны; всё остальное (например, слишком много открытых
/// файлов) логируется с задержкой, чтобы цикл не крутился вхолостую.
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
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/peer",
            get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.ip().to_string() }),
        );
        let (stop, stopped) = oneshot::channel::<()>();
        let limits = Limits {
            header_read_timeout,
            max_connections: 16,
            shutdown_grace: Duration::from_secs(1),
        };
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

    #[tokio::test]
    async fn slow_headers_are_cut_off() {
        let (addr, stop, handle) = start(Duration::from_millis(200)).await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        // заголовки так и не поступили
        s.write_all(b"GET /peer HTTP/1.1\r\nHost: x\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let closed = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await;
        assert!(
            closed.is_ok(),
            "connection still open after the header timeout"
        );
        stop.send(()).unwrap();
        handle.await.unwrap();
    }
}
