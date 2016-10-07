#!/usr/bin/env ruby

require_relative '../lib/barkest_ssh/secure_shell'
require 'io/console'

if $0 == __FILE__

  print 'Enter host: '
  test_host = STDIN.gets.strip
  raise 'host is required' if test_host == ''

  print 'Enter user: '
  test_user = STDIN.gets.strip
  raise 'user is required' if test_user == ''

  print 'Enter password: '
  test_password = STDIN.noecho(&:gets).strip
  print "\n"
  raise 'password is required' if test_password == ''

  ShellTestError = Class.new(BarkestSsh::SecureShell::ShellError)

  local_home = File.expand_path('~')

  begin
    print 'Connecting ... '
    ::BarkestSsh::SecureShell.new(
        host: test_host,
        user: test_user,
        password: test_password
    ) do |shell|
      print "Connected!\n"


      print 'Executing "ls -al" ... '
      results = shell.exec('ls -al').split("\n")
      print "Done (#{results.count} lines)\n"

      test_file = '/a-test-file-that-can-be-deleted'

      print 'Executing long command ... '
      results = shell.exec("touch ~#{test_file} >/dev/null && echo the-file-was-touched || echo the-file-was-not-touched").strip
      raise ShellTestError, 'result should not be blank' if results == ''
      print "Done (#{results})\n"

      print 'Executing invalid command ... '
      begin
        shell.exec_raise 'do-something-invalid this should return an exit code of 127 since the command should not be found'
        raise ShellTestError, "an error should have been raised and the exit code (#{shell.last_exit_code}) should not be zero"
      rescue ::BarkestSsh::SecureShell::NonZeroExitCode
        print "Done (Received error as expected)\n"
      end

      print 'Executing sudo command ... '
      begin
        results = shell.sudo_exec('echo "user is a sudoer"').strip
        raise ShellTestError, 'result should not be blank' if results == ''
        print "Done (#{results})\n"
      rescue ::BarkestSsh::SecureShell::NonZeroExitCode
        print "Done (user does not appear to be a sudoer)\n"
      end

      print 'Getting remote home path ... '
      remote_home = shell.exec("eval echo \"~#{test_user}\"").strip
      raise ShellTestError, 'result should not be blank' if remote_home == ''
      print "Done (#{remote_home})\n"

      print 'Creating SFTP session ... '
      results = shell.send(:sftp)
      raise ShellTestError, 'no session created' if results.nil?
      raise ShellTestError, 'connection not open' unless results.open?
      print "Done\n"

      test_contents = 'This is my test file that was written at ' + Time.now.strftime('%Y-%m-%d %H:%M:%S')

      print 'Writing a test file ... '
      shell.write_file(remote_home + test_file, test_contents)
      print "Done\n"

      print 'Reading a test file ... '
      read_results = shell.read_file(remote_home + test_file)
      raise ShellTestError, 'contents do not match' unless read_results == test_contents
      print "Done\n"

      print 'Uploading a test file ... '
      test_contents += ' (from local)'
      File.write(local_home + test_file, test_contents)
      shell.upload(local_home + test_file, remote_home + test_file)
      print "Done\n"

      print 'Downloading a test file ... '
      File.delete(local_home + test_file)
      shell.download(remote_home + test_file, local_home + test_file)
      read_results = File.read(local_home + test_file)
      raise ShellTestError, 'contents do not match' unless read_results == test_contents
      print "Done\n"

      print 'Cleaning up ... '
      shell.exec "rm ~#{test_file}"
      File.delete local_home + test_file
      print "Done\n"

    end

    print "All basic tests have completed.\n"
  rescue =>e
    print "FAILED (#{e.is_a?(BarkestSsh::SecureShell::ShellError) ? e.message : e.to_s})\n"
    if e.is_a?(Exception)
      print e.backtrace.first.to_s + "\n"
    end
  end

end