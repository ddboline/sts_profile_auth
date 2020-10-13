# sts_profile_auth

[![crates.io](https://meritbadge.herokuapp.com/sts_profile_auth)](https://crates.io/crates/sts_profile_auth)
[![Build Status](https://github.com/ddboline/sts_profile_auth/workflows/Rust/badge.svg?branch=master)](https://github.com/ddboline/sts_profile_auth/actions?branch=master)
[![Documentation](https://docs.rs/sts_profile_auth/badge.svg)](https://docs.rs/sts_profile_auth/)
[![codecov](https://codecov.io/gh/ddboline/sts_profile_auth/branch/master/graph/badge.svg)](https://codecov.io/gh/ddboline/sts_profile_auth)

This crate extends [Rusoto's](https://crates.io/crates/rusoto) existing authentication infrastructure to let you use [profiles specified in a config or credentials file](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html).  The entries look something like:

```bash
[profile special-profile]
region = us-east-1
role_arn = arn:aws:iam:867530912345:role/Special_Role
source_profile = default
```

This crate extends [Rusoto's](https://crates.io/crates/rusoto) existing authentication infrastructure to support this feature.

Usage:

```rust
    use rusoto_core::Region;
    use rusoto_ec2::Ec2Client;
    use sts_profile_auth::get_client_sts;

    fn main() -> Result<(), Error> {
        let ec2 = get_client_sts!(Ec2Client)?;
        Ok(())
    }
```