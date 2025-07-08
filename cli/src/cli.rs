use clap::Arg;

// Helper functions for creating common arguments
pub fn server_arg() -> Arg {
    Arg::new("server")
        .help("Server URL")
        .short('s')
        .long("server")
        .default_value("http://localhost:3000")
}

pub fn keypair_arg() -> Arg {
    Arg::new("keypair")
        .help("Path to keypair file")
        .short('k')
        .long("keypair")
        .required(true)
}

pub fn post_id_arg() -> Arg {
    Arg::new("post_id")
        .help("Post ID")
        .short('p')
        .long("post-id")
        .required(true)
}

pub fn document_id_arg() -> Arg {
    Arg::new("document_id")
        .help("Document ID")
        .short('d')
        .long("document-id")
        .required(true)
}

pub fn optional_post_id_arg() -> Arg {
    Arg::new("post_id")
        .help("Post ID to add revision to (creates new post if not provided)")
        .short('p')
        .long("post-id")
}

pub fn identity_pod_arg() -> Arg {
    Arg::new("identity_pod")
        .help("Path to identity pod file")
        .short('i')
        .long("identity-pod")
        .required(true)
}

pub fn mock_arg() -> Arg {
    Arg::new("mock")
        .help("Use mock provers for faster testing")
        .long("mock")
        .action(clap::ArgAction::SetTrue)
}
