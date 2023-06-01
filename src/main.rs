mod ghsa;
mod nvd;

fn main() {
    let ghsa = ghsa::fetch().unwrap();

    println!("+------------------------------+");

    for edge in ghsa.data.security_advisories.edges {
        let node = edge.node;
        println!("{}", node.ghsa_id);
        println!("{}", node.summary);
        println!("{}", node.cvss.vector_string.unwrap_or("N/A".to_string()));
        println!("{}", node.severity);
        println!("+------------------------------+");
    }
}
