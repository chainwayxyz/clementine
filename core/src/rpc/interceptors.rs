use tonic::{service::Interceptor, transport::CertificateDer, GrpcMethod, Request, Status};

#[derive(Debug, Clone)]
pub enum Interceptors {
    OnlyAggregatorAndSelf {
        aggregator_cert: CertificateDer<'static>,
        our_cert: CertificateDer<'static>,
    },
    Noop,
}

fn is_internal(req: &Request<()>) -> bool {
    let Some(path) = req.extensions().get::<GrpcMethod>() else {
        // No grpc method? this should not happen
        return false;
    };

    path.method().starts_with("Internal")
}

impl Interceptor for Interceptors {
    fn call(&mut self, req: Request<()>) -> Result<Request<()>, Status> {
        match self {
            Interceptors::OnlyAggregatorAndSelf {
                our_cert,
                aggregator_cert,
            } => only_aggregator_and_self(req, our_cert, aggregator_cert),
            Interceptors::Noop => Ok(req),
        }
    }
}

fn only_aggregator_and_self(
    req: Request<()>,
    our_cert: &CertificateDer<'static>,
    aggregator_cert: &CertificateDer<'static>,
) -> Result<Request<()>, Status> {
    let Some(peer_certs) = req.peer_certs() else {
        if cfg!(test) {
            // Test mode, we don't need to verify peer certificates
            return Ok(req);
        } else {
            // If we're not in test mode, we need to check peer certificates
            return Err(Status::unauthenticated(
                "Failed to verify peer certificate, is TLS enabled?",
            ));
        }
    };

    if is_internal(&req) {
        if peer_certs.contains(our_cert) {
            Ok(req)
        } else {
            Err(Status::unauthenticated(
                "Unauthorized call to internal method (not self)",
            ))
        }
    } else if peer_certs.contains(aggregator_cert) || peer_certs.contains(our_cert) {
        Ok(req)
    } else {
        Err(Status::unauthenticated(
            "Unauthorized call to method (not aggregator or self)",
        ))
    }
}
