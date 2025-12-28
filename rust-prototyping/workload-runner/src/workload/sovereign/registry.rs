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
use std::collections::HashMap;
use std::sync::Arc;

use super::trustplane::TrustPlane;
use super::WorkloadIdentity;

pub struct Registry {
    identities: HashMap<String, Arc<WorkloadIdentity>>,
    trustplane: Arc<TrustPlane>,
}

impl Registry {
    pub fn load() -> Result<Self> {
        let names = [
            "sovereign-trustplane",
            "sovereign-gateway",
            "sovereign-archive",
            "sovereign-storage",
        ];
        let mut identities = HashMap::new();

        for name in names {
            let identity = WorkloadIdentity::load(name)?;
            identities.insert(name.to_string(), Arc::new(identity));
        }

        let tp_identity = WorkloadIdentity::load("sovereign-trustplane")?;
        let trustplane = Arc::new(TrustPlane::new_with_fallback(tp_identity));

        println!("📂 Registry: loaded {} identities", identities.len());
        println!("🔐 TrustPlane: {}", trustplane.did());
        println!("   Using real key: {}", trustplane.has_real_key());

        Ok(Self {
            identities,
            trustplane,
        })
    }

    pub fn get(&self, name: &str) -> Option<Arc<WorkloadIdentity>> {
        self.identities.get(name).cloned()
    }

    pub fn trustplane(&self) -> Arc<TrustPlane> {
        self.trustplane.clone()
    }
}