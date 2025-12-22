use anyhow::Result;

mod identity_gen;

use identity_gen::{trustplane_gen, workload_gen};

#[tokio::main]
async fn main() -> Result<()> {
    println!("🔐 Workload Identity Generator\n");

    // Demo federations representing two deployment models:
    // Each federation owns its domain - PIC is just the protocol, not a platform
    //
    // - "sovereign": Enterprise on-prem (banks, healthcare, government)
    //                Self-hosted infrastructure, strict compliance, internal CAT
    // - "nomad": Cloud-native (startups, SaaS, platforms)  
    //            Multi-cloud (AWS/GCP/Azure), Kubernetes, distributed CAT
    let federations = [
        ("sovereign", "sovereign.example"),
        ("nomad", "nomad.example"),
    ];

    for (name, domain) in federations {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("🌐 Federation: {} ({})\n", name, domain);

        let trustplane = trustplane_gen(
            &format!("{}-trustplane", name),
            &format!("trustplane.{}", domain),
        ).await?;

        println!();

        for workload in ["gateway", "archive", "storage"] {
            workload_gen(
                &format!("{}-{}", name, workload),
                &format!("{}.{}", workload, domain),
                &trustplane,
            ).await?;
            println!();
        }
    }

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("✅ All federations generated!");
    Ok(())
}