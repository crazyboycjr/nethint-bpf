use std::iter;
use std::process::Command;
use std::str;
use tracing::debug;

pub fn get_command_str(cmd: &Command) -> String {
    let prog = cmd.get_program().to_str().unwrap();
    let args: Vec<&str> = cmd.get_args().map(|x| x.to_str().unwrap()).collect();
    let cmd_str = iter::once(prog).chain(args).collect::<Vec<_>>().join(" ");
    cmd_str
}

pub fn get_command_output_string(cmd: Command) -> anyhow::Result<String> {
    let stdout = get_command_output(cmd)?;
    Ok(str::from_utf8(&stdout)?.to_owned())
}

pub fn get_command_output(mut cmd: Command) -> anyhow::Result<Vec<u8>> {
    let cmd_str = get_command_str(&cmd);
    debug!("executing command: {}", cmd_str);

    use std::os::unix::process::ExitStatusExt; // for status.signal()
    let result = cmd.output()?;

    if !result.status.success() {
        return match result.status.code() {
            Some(code) => Err(anyhow::anyhow!(
                "Exited with code: {}, cmd: {}",
                code,
                cmd_str
            )),
            None => Err(anyhow::anyhow!(
                "Process terminated by signal: {}, cmd: {}",
                result.status.signal().unwrap(),
                cmd_str,
            )),
        };
    }

    Ok(result.stdout)
}
