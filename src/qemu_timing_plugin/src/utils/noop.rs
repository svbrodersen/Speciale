use super::DomainRetriever;

pub struct NoOpRetriever;

impl DomainRetriever for NoOpRetriever {
    fn new(_cores: usize, _elf_file: &str) -> Self {
        Self
    }
    fn get_domain_info(&self, _vcpu_index: u32, _pc: usize) -> Option<(usize, bool)> {
        None
    }

    fn vcpu_init(&self) {}
    fn on_exit(&self, _out: &mut String) {}
}
