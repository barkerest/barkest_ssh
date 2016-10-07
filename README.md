# BarkestSsh

The BarkestSsh gem is a very simple wrapper around Net::SSH.  Using the BarkestSsh::SecureShell class you can execute a
shell session on a local or remote host.  Primarily targeted at `bash` shells, this gem may have trouble interacting 
with some hardware due to some assumptions it makes.

For instance, it expects to be able to set the `PS1` variable to use a custom prompt so it knows when command execution
has officially completed.  A possible workaround if the device has a static shell is to set the prompt option to match
the static shell.  If the device has a dynamic shell, but a static final sequence (ie - '>', '$', or '#') then setting 
the prompt option to that value may also work.  However, there may be an issue with false positives in this situation.

This gem was primarily developed to be added into [Barker EST](http://www.barkerest.com/) web applications (hence the name).


## Installation

Add this line to your application's Gemfile:

```ruby
gem 'barkest_ssh'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install barkest_ssh

## Usage

All of the work is done in the BarkestSsh::SecureShell constructor.  Provide a code block to BarkestSsh::SecureShell.new
with the actions you want to execute remotely.

```ruby
BarkestSsh::SecureShell.new(
    host: '10.10.10.10',
    user: 'somebody',
    password: 'super-secret'
) do |shell|
  shell.exec('cd /usr/local/bin')
  user_bin_files = shell.exec('ls -A1').split('\n')
  @app_is_installed = user_bin_files.include?('my_app')
end
```


The following methods are available within the code block:

* __`exec(command, options = {}, &block)`__
  
  This is the core method that will probably be used most often.  The command is executed and the text sent
  to STDOUT and STDERR is returned as a single string for you to process.  The options parameter can set the
  `:on_non_zero_exit_code` option to :default, :ignore, or :raise_error.  If a block is provided, the block
  will be called anytime data is received.  The block will receive data and type parameters.  Type will indicate
  if the data was sent to STDOUT or STDERR.  If the block returns a value, that value will be sent to the shell.
  This can be used to interact with the shell.
  
* __`exec_ignore(command, &block)`__
  
  Wrapper for `exec` that sets :on_non_zero_exit_code to :ignore.
  
* __`exec_raise(command, &block)`__
  
  Wrapper for `exec` that sets :on_non_zero_exit_code to :raise_error.

* __`sudo_exec(command, options = {}, &block)`__

  Wrapper for `exec` that attempts to elevate the command to run as root.  This will only work if the user
  that the shell is connected with is a sudoer on the target host.  Also, it requires that the target host
  uses the `sudo` command and `bash` shell.

* __`sudo_exec_ignore(command, &block)`__
    
  Wrapper for `sudo_exec` that sets :on_non_zero_exit_code to :ignore.
  
* __`sudo_exec_raise(command, &block)`__
  
  Wrapper for `sudo_exec` that sets :on_non_zero_exit_code to :raise_error.

* __`last_exit_code`__
  
  Gets the exit code from the last command, if the shell is configured to retrieve the exit codes.

* __`stdout`__
  
  Gets the output to STDOUT for the shell session.

* __`stderr`__
  
  Gets the output to STDERR for the shell session.

* __`combined_output`__
  
  Gets the output to both STDOUT and STDERR combined together for the shell session.

* __`upload(local_file, remote_file)`__
  
  Uses a SFTP channel to upload a file to the host.  The first time a SFTP method is used a second
  SSH connection is made to the host and a SFTP channel is created.

* __`download(remote_file, local_file)`__

  Uses a SFTP channel to download a file from the host. The first time a SFTP method is used a second
  SSH connection is made to the host and a SFTP channel is created.
  
* __`read_file(remote_file)`__
  
  Uses a SFTP channel to download a file from the host and returns the contents as a string.
  The first time a SFTP method is used a second SSH connection is made to the host and a SFTP channel
  is created.

* __`write_file(remote_file, data)`__

  Uses a SFTP channel to upload a file to the host from an in-memory string.
  The first time a SFTP method is used a second SSH connection is made to the host and a SFTP channel
  is created.


## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/barkerest/barkest_ssh.


## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

Copyright (c) 2016 [Beau Barker](mailto:beau@barkerest.com)
