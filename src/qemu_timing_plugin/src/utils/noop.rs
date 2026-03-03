use super::DomainRetriever;

pub struct NoOpRetriever;

impl DomainRetriever for NoOpRetriever {
    fn new(_cores: usize) -> Self {
        Self
    }
    fn get_domain_id(&self, _vcpu_index: u32) -> Option<usize> {
        None
    }

    fn vcpu_init(&self) {}
    fn on_exit(&self, _out: &mut String) {}
}
