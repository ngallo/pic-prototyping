use anyhow::Result;

mod identity_gen;

use identity_gen::{trustplane_gen, workload_gen, WorkloadIdentityType};

#[tokio::main]
async fn main() -> Result<()> {
    println!("🔐 Workload Identity Generator\n");

    // Demo federations representing two deployment models:
    // Each federation owns its domain - PIC is just the protocol, not a platform
    //
    // - "sovereign": Enterprise on-prem with SPIFFE/SPIRE
    // - "nomad": Cloud-native Kubernetes workloads
    let federations = [
        ("sovereign", "sovereign.example", "spiffe"),
        ("nomad", "nomad.example", "kubernetes"),
    ];

    for (name, domain, identity_system) in federations {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("🌐 Federation: {} ({}) - {}\n", name, domain, identity_system);

        let trustplane = trustplane_gen(
            &format!("{}-trustplane", name),
            &format!("trustplane.{}", domain),
        ).await?;

        println!();

        for workload in ["gateway", "archive", "storage"] {
            let workload_name = format!("{}-{}", name, workload);
            let workload_domain = format!("{}.{}", workload, domain);
            
            let identity_type = match identity_system {
                "spiffe" => WorkloadIdentityType::Spiffe {
                    spiffe_id: format!("spiffe://{}/{}", domain, workload),
                },
                "kubernetes" => WorkloadIdentityType::Kubernetes {
                    namespace: format!("{}-prod", name),
                    service_account: format!("{}-sa", workload),
                },
                _ => WorkloadIdentityType::Did {
                    did: format!("did:web:{}", workload_domain),
                },
            };

            workload_gen(
                &workload_name,
                &workload_domain,
                identity_type,
                &trustplane,
            ).await?;
            println!();
        }
    }

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("✅ All federations generated!");
    Ok(())
}
