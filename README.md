# BarkestSsh

The BarkestSsh gem is a very simple wrapper around Net::SSH.  Using the BarkestSsh::SecureShell class you can execute a
shell session on a local or remote host.

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

## Development

After checking out the repo, run `bin/setup` to install dependencies. You can also run `bin/console` for an interactive
prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version
number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git
commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/barkest_ssh.


## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

