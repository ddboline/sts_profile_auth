# sts_profile_auth
This crate extends [Rusoto's](https://crates.io/crates/rusoto) existing authentication infrastructure to let you use [profiles specified in a config or credentials file](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html).  The entries look something like:

```bash
[profile special-profile]
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
        let region = Region::UsEast1;
        let ec2 = get_client_sts!(Ec2Client, region)?;
        Ok(())
    }
```