use std::future::Future;
use tonic::transport::Uri;

#[allow(clippy::all)]
#[rustfmt::skip]
pub mod clementine;
pub mod aggregator;
pub mod operator;
pub mod verifier;
pub mod watchtower;
mod wrapper;

pub async fn get_clients<CLIENT, F, Fut>(
    endpoints: Vec<String>,
    connect: F,
) -> Result<Vec<CLIENT>, tonic::transport::Error>
where
    F: FnOnce(Uri) -> Fut + Clone,
    Fut: Future<Output = Result<CLIENT, tonic::transport::Error>>,
{
    futures::future::try_join_all(endpoints.iter().map(|endpoint| {
        let endpoint_clone = endpoint.clone();
        let connect_clone = connect.clone();

        async move {
            let uri = Uri::try_from(endpoint_clone).unwrap();
            let client = connect_clone(uri).await.unwrap();
            Ok(client)
        }
    }))
    .await
}
