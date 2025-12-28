/*
 * Copyright Nitro Agility S.r.l.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use anyhow::Result;
use std::sync::Arc;
use super::{WorkloadIdentity, Request, Response, registry::Registry};

pub struct Storage {
    identity: Arc<WorkloadIdentity>,
}

impl Storage {
    pub fn new(registry: Arc<Registry>) -> Result<Self> {
        let identity = registry.get("sovereign-storage")
            .ok_or_else(|| anyhow::anyhow!("sovereign-storage not found in registry"))?;
        Ok(Self { identity })
    }
    
    pub fn load() -> Result<Self> {
        let registry = Arc::new(Registry::load()?);
        Self::new(registry)
    }

    async fn process(&self, request: Request) -> Result<Response> {
        let output_file = format!("/user/output_{}.txt", timestamp());
        let data = format!("Processed: {}", request.content);
        Ok(Response { output_file, data })
    }

    pub async fn next(&self, request: Request) -> Result<Response> {
        self.identity.print();
        println!("   → Processing request");
        let response = self.process(request).await?;
        println!("   ✓ Written: {}", response.output_file);
        Ok(response)
    }
}

fn timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}