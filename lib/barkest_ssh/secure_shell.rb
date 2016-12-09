
require 'net/ssh'
require 'net/sftp'

module BarkestSsh

  ##
  # The SecureShell class is used to run an SSH session with a local or remote host.
  #
  # This is a wrapper for Net::SSH that starts a shell session and executes a block.
  # All of the output from the session is cached for later use as needed.
  #
  class SecureShell

    ##
    # An error occurring within the SecureShell class aside from argument errors.
    ShellError = Class.new(StandardError)

    ##
    # An exception raised when a command requiring a connection is attempted after the connection has been closed.
    ConnectionClosed = Class.new(ShellError)

    ##
    # An exception raised when the SSH session fails to request a PTY.
    FailedToRequestPTY = Class.new(ShellError)

    ##
    # An exception raised when the SSH session fails to start a shell.
    FailedToStartShell = Class.new(ShellError)

    ##
    # An exception raised when the SSH shell session fails to execute.
    #
    FailedToExecute = Class.new(ShellError)

    ##
    # An exception raised when the shell session is silent too long.
    LongSilence = Class.new(ShellError)

    ##
    # A command exited with a non-zero status.
    NonZeroExitCode = Class.new(ShellError)

    ##
    # Creates a SecureShell session and executes the provided block.
    #
    # You must provide a code block to run within the shell session, the session is closed before this returns.
    #
    # Valid options:
    # *   +host+
    #     The name or IP address of the host to connect to.  Defaults to 'localhost'.
    # *   +port+
    #     The port on the host to connect to.  Defaults to 22.
    # *   +user+
    #     The user to login with.
    # *   +password+
    #     The password to login with.
    # *   +prompt+
    #     The prompt used to determine when processes finish execution.
    #     Defaults to '~~#', but if that doesn't work for some reason because it is valid output from one or more
    #     commands, you can change it to something else.  It must be unique and cannot contain certain characters.
    #     The characters you should avoid are !, $, \, /, ", and ' because no attempt is made to escape them and the
    #     resulting prompt can very easily become something else entirely.  If they are provided, they will be
    #     replaced to protect the shell from getting stuck.
    # *   +silence_wait+
    #     The number of seconds to wait when the shell is not sending back data to send a newline.  This can help
    #     battle background tasks burying the prompt, but it might not play nice with long-running foreground tasks.
    #     The default is 5 seconds, if you notice problems, set this to a higher value, or 0 to disable.
    #     During extended silence, the first time this value elapses, the shell will send the newline, the second time
    #     the shell will error out.
    # *   +replace_cr+
    #     The string to replace stand-alone CR characters with.  The default is an empty string (ie - remove them).
    #     You may also want to replace with a LF character instead, which is the behavior taken when a CR+ LF sequence
    #     is encountered.  A space followed by a standalone CR is treated differently since these seem to occur when
    #     the terminal ouput wraps.  In these cases, the SPACE + CR sequence is simply removed.
    # *   +retrieve_exit_code+
    #     Version 1.1.10 introduces support for grabbing the exit code from the last command and then performing an
    #     action.  The default value is true, but if you set this to false then the shell will not retrieve the exit
    #     codes automatically.
    # *   +on_non_zero_exit_code+
    #     If the exit code is non-zero, the default behavior (to remain compatible with prior versions) is to
    #     ignore the exit code.  You can also set this to :raise_error to raise the NonZeroExitCode error.
    # *   +filter_password+
    #     As a convenience, if this is set to true (the default), then any text matching the configured password
    #     will be replaced with a series of asterisks in the output.
    #
    #   SecureShell.new(
    #       host: '10.10.10.10',
    #       user: 'somebody',
    #       password: 'super-secret'
    #   ) do |shell|
    #     shell.exec('cd /usr/local/bin')
    #     user_bin_files = shell.exec('ls -A1').split('\n')
    #     @app_is_installed = user_bin_files.include?('my_app')
    #   end
    #
    def initialize(options = {}, &block)
      options ||= {}
      @options = {
          host: options[:host] || 'localhost',
          port: options[:port] || 22,
          user: options[:user],
          password: options[:password],
          prompt: (options[:prompt].to_s.strip == '') ? '~~#' : options[:prompt],
          silence_wait: (options[:silence_wait] || 5),
          replace_cr: options[:replace_cr].to_s,
          retrieve_exit_code: options[:retrieve_exit_code].nil? ? true : options[:retrieve_exit_code],
          on_non_zero_exit_code: options[:on_non_zero_exit_code] ? options[:on_non_zero_exit_code].to_s.to_sym : :ignore,
          filter_password: options[:filter_password].nil? ? true : options[:filter_password],
      }

      raise ArgumentError.new('Missing block.') unless block_given?
      raise ArgumentError.new('Missing host.') if @options[:host].to_s.strip == ''
      raise ArgumentError.new('Missing user.') if @options[:user].to_s.strip == ''
      raise ArgumentError.new('Missing password.') if @options[:password].to_s.strip == ''
      raise ArgumentError.new('Missing prompt.') if @options[:prompt].to_s.strip == ''
      raise ArgumentError.new('Invalid option for on_non_zero_exit_code.') unless [:ignore, :raise_error].include?(@options[:on_non_zero_exit_code])

      @options[:prompt] = @options[:prompt]
                              .gsub('!', '#')
                              .gsub('$', '#')
                              .gsub('\\', '.')
                              .gsub('/', '.')
                              .gsub('"', '-')
                              .gsub('\'', '-')

      executed = false

      @last_exit_code = 0
      @sftp = nil
      Net::SSH.start(
          @options[:host],
          @options[:user],
          password: @options[:password],
          port: @options[:port],
          non_interactive: true,
      ) do |ssh|
        @ssh = ssh
        ssh.open_channel do |ssh_channel|
          ssh_channel.request_pty do |pty_channel, pty_success|
            raise FailedToRequestPTY.new('Failed to request PTY.') unless pty_success

            pty_channel.send_channel_request('shell') do |_, shell_success|
              raise FailedToStartShell.new('Failed to start shell.') unless shell_success

              # cache the channel pointer and start buffering the input.
              @channel = pty_channel
              buffer_input

              # give the shell a chance to catch up and initialize fully.
              sleep 0.25

              # set the shell prompt so that we can determine when processes end.
              # does not work with background processes since we are looking for
              # the shell to send us this when it is ready for more input.
              # a background process can easily bury the prompt and then we are stuck in a loop.
              exec "PS1=\"#{@options[:prompt]}\""

              block.call(self)

              executed = true

              # send the exit command and remove the channel pointer.
              quit
              @channel = nil
            end
          end
          ssh_channel.wait
        end
      end

      @ssh = nil

      if @sftp
        @sftp.session.close
        @sftp = nil
      end

      # remove the cached user and password.
      options.delete(:user)
      options.delete(:password)

      raise FailedToExecute.new('Failed to execute shell.') unless executed
    end

    ##
    # Gets the last exit code.
    def last_exit_code
      @last_exit_code || 0
    end

    ##
    # Wrapper for +exec+ that will ignore non-zero exit codes.
    def exec_ignore(command, &block)
      exec command, on_non_zero_exit_code: :ignore, &block
    end

    ##
    # Wrapper for +exec+ that will raise an error on non-zero exit codes.
    def exec_raise(command, &block)
      exec command, on_non_zero_exit_code: :raise_error, &block
    end

    ##
    # Executes a command during the shell session.
    #
    # If called outside of the +new+ block, this will raise an error.
    #
    # The +command+ is the command to execute in the shell.
    #
    # The +options+ parameter can include the following keys.
    # *  The :on_non_zero_exit_code option can be :default, :ignore, or :raise_error.
    #
    # If provided, the +block+ is a chunk of code that will be processed every time the
    # shell receives output from the program.  If the block returns a string, the string
    # will be sent to the shell.  This can be used to monitor processes or monitor and
    # interact with processes.  The +block+ is optional.
    #
    #   shell.exec('sudo -p "password:" nginx restart') do |data,type|
    #     return 'super-secret' if /password:$/.match(data)
    #     nil
    #   end
    #
    def exec(command, options={}, &block)
      raise ConnectionClosed.new('Connection is closed.') unless @channel

      options = {
          on_non_zero_exit_code: :default
      }.merge(options || {})

      options[:on_non_zero_exit_code] = @options[:on_non_zero_exit_code] if options[:on_non_zero_exit_code] == :default

      push_buffer # store the current buffer and start a fresh buffer

      # buffer while also passing data to the supplied block.
      if block_given?
        buffer_input( &block )
      end

      # send the command and wait for the prompt to return.
      @channel.send_data command + "\n"
      wait_for_prompt

      # return buffering to normal.
      if block_given?
        buffer_input
      end

      # get the output from the command, minus the trailing prompt.
      ret = command_output(command)

      # restore the original buffer and merge the output from the command.
      pop_merge_buffer

      if @options[:retrieve_exit_code]
        # get the exit code for the command.
        push_buffer
        retrieve_command = 'echo $?'
        @channel.send_data retrieve_command + "\n"
        wait_for_prompt
        @last_exit_code = command_output(retrieve_command).strip.to_i
        # restore the original buffer and discard the output from this command.
        pop_discard_buffer

        # if we are expected to raise an error, do so.
        if options[:on_non_zero_exit_code] == :raise_error
          raise NonZeroExitCode.new("Exit code was #{@last_exit_code}.") unless @last_exit_code == 0
        end
      end

      ret
    end

    ##
    # Wrapper for +sudo_exec+ that will ignore non-zero exit codes.
    def sudo_exec_ignore(command, &block)
      sudo_exec command, on_non_zero_exit_code: :ignore, &block
    end

    ##
    # Wrapper for +sudo_exec+ that will raise an error on non-zero exit codes.
    def sudo_exec_raise(command, &block)
      sudo_exec command, on_non_zero_exit_code: :raise_error, &block
    end

    ##
    # Executes a command using +sudo+ during the shell session.
    #
    # This is a wrapper around +exec+ that attempts to run the command as root.
    # It provides the configured user's password if/when prompted.
    #
    # See +exec+ for more information.
    def sudo_exec(command, options = {}, &block)
      sudo_prompt = '[sp:'
      sudo_match = /(\r|\n)\[sp\:$/
      sudo_strip = /\[sp\:\n/
      ret = exec("sudo -p \"#{sudo_prompt}\" bash -c \"#{command.gsub('"', '\\"')}\"", options) do |data,type|
        test_data = data.to_s
        desired_length = sudo_prompt.length + 1 # prefix a NL before the prompt.

        # pull from the current stdout to get the full test data, but only if we received some new data.
        if test_data.length > 0 && test_data.length < desired_length
          test_data = stdout[-desired_length..-1].to_s
        end

        if sudo_match.match(test_data)
          @options[:password]
        else
          if block
            block.call(data, type)
          else
            nil
          end
        end
      end
      # remove the sudo prompts.
      ret.gsub(sudo_strip, '')
    end

    ##
    # Uses SFTP to upload a single file to the host.
    def upload(local_file, remote_file)
      raise ConnectionClosed.new('Connection is closed.') unless @ssh
      sftp.upload!(local_file, remote_file)
    end

    ##
    # Uses SFTP to download a single file from the host.
    def download(remote_file, local_file)
      raise ConnectionClosed.new('Connection is closed.') unless @ssh
      sftp.download!(remote_file, local_file)
    end

    ##
    # Uses SFTP to read the contents of a single file.
    #
    # Returns the contents of the file.
    def read_file(remote_file)
      raise ConnectionClosed.new('Connection is closed.') unless @ssh
      sftp.download!(remote_file)
    end

    ##
    # Uses SFTP to write data to a single file.
    def write_file(remote_file, data)
      raise ConnectionClosed.new('Connection is closed.') unless @ssh
      sftp.file.open(remote_file, 'w') do |f|
        f.write data
      end
    end

    ##
    # Gets the standard output from the session.
    #
    # The prompts are stripped from the standard ouput as they are encountered.
    # So this will be a list of commands with their output.
    #
    # All line endings are converted to LF characters, so you will not
    # encounter or need to search for CRLF or CR sequences.
    #
    def stdout
      @stdout || ''
    end

    ##
    # Gets the error output from the session.
    #
    # All line endings are converted to LF characters, so you will not
    # encounter or need to search for CRLF or CR sequences.
    #
    def stderr
      @stderr || ''
    end

    ##
    # Gets both the standard output and error output from the session.
    #
    # The prompts will be included in the combined output.
    # There is no attempt to differentiate error output from standard output.
    #
    # This is essentially the definitive log for the session.
    #
    # All line endings are converted to LF characters, so you will not
    # encounter or need to search for CRLF or CR sequences.
    #
    def combined_output
      @stdcomb || ''
    end

    private

    def quit
      raise ConnectionClosed.new('Connection is closed.') unless @channel
      @channel.send_data("exit\n")
      @channel.wait
    end

    def command_output(command)
      # get everyting except for the ending prompt.
      ret = combined_output[0...-(@options[:prompt].length)]
      # return the output from the command starting with the second line.
      # the first line is the command sent to the shell.
      # We also check for those rare times when a prompt manages to sneak in, trimming them off the front as well.
      result_cmd,_,result_data = ret.partition("\n")
      cmd_with_prompt = @options[:prompt] + command
      until result_cmd == command || result_cmd == cmd_with_prompt || result_data.to_s.strip == ''
        result_cmd,_,result_data = result_data.partition("\n")
      end
      result_data
    end

    def stdout_hist
      @stdout_hist ||= []
    end

    def stderr_hist
      @stderr_hist ||= []
    end

    def stdcomb_hist
      @stdcom_hist ||= []
    end

    def prompted?
      @prompted ||= false
    end

    def reset_prompted
      @prompted = false
    end

    def set_prompted
      @prompted = true
    end

    def push_buffer
      # push the buffer so we can get the output of a command.
      stdout_hist.push stdout
      stderr_hist.push stderr
      stdcomb_hist.push combined_output
      @stdout = ''
      @stderr = ''
      @stdcomb = ''
    end

    def pop_merge_buffer
      # almost a standard pop, however we want to merge history with current.
      if (hist = stdout_hist.pop)
        @stdout = hist + stdout
      end
      if (hist = stderr_hist.pop)
        @stderr = hist + stderr
      end
      if (hist = stdcomb_hist.pop)
        @stdcomb = hist + combined_output
      end
    end

    def pop_discard_buffer
      # a standard pop discarding current data and retrieving the history.
      if (hist = stdout_hist.pop)
        @stdout = hist
      end
      if (hist = stderr_hist.pop)
        @stderr = hist
      end
      if (hist = stdcomb_hist.pop)
        @stdcomb = hist
      end
    end

    def append_stdout(data, &block)
      # Combined output gets the prompts,
      # but stdout will be without prompts.
      # CRLF are converted to LF and CR are removed.
      # The " \r" sequence appears to be a line continuation sequence for the shell, so it get's removed.
      # All remaining CR are replaced with LF.
      data = data.gsub("\r\n", "\n").gsub(" \r", '').gsub("\r", @options[:replace_cr])

      for_stdout = if data[-(@options[:prompt].length)..-1] == @options[:prompt]
                     set_prompted
                     data[0...-(@options[:prompt].length)]
                   else
                     data
                   end

      @stdout = @stdout.to_s + for_stdout
      @stdcomb = @stdcomb.to_s + data

      if block_given?
        result = block.call(for_stdout, :stdout)
        if result && result.is_a?(String)
          @channel.send_data(result + "\n") if @channel
        end
      end
    end

    def append_stderr(data, &block)
      data = data.gsub("\r\n", "\n").gsub(" \r", '').gsub("\r", @options[:replace_cr])

      @stderr = @stderr.to_s + data
      @stdcomb = @stdcomb.to_s + data

      if block_given?
        result = block.call(data, :stderr)
        if result && result.is_a?(String)
          @channel.send_data(result + "\n") if @channel
        end
      end
    end

    def buffer_input(&block)
      raise ConnectionClosed.new('Connection is closed.') unless @channel
      block ||= Proc.new { }

      @last_input = Time.now

      @channel.on_data do |_, data|
        append_stdout strip_ansi_escape(sterilize(data)), &block
      end

      @channel.on_extended_data do |_, type, data|
        if type == 1
          append_stderr strip_ansi_escape(sterilize(data)), &block
        end
      end

    end

    def wait_for_prompt
      raise ConnectionClosed.new('Connection is closed.') unless @channel

      wait_timeout = @options[:silence_wait].to_s.to_i
      @last_input ||= Time.now
      sent_nl_at = nil
      sent_nl_times = 0

      @channel.connection.loop do
        # cache the last input, this way if something is received it doesn't screw with us.
        last_input = @last_input

        # do we need to nudge the shell?
        if wait_timeout > 0 && (Time.now - last_input) > wait_timeout

          # have we nudged the shell more than twice?
          if sent_nl_times > 2
            raise LongSilence.new('No input from shell for extended period.')
          else

            # reset the timer and increment the counter if the timer hasn't budged since we last nudged it.
            sent_nl_times = (sent_nl_at.nil? || sent_nl_at < last_input) ? 1 : (sent_nl_times + 1)
            sent_nl_at = Time.now

            # and send the NL to nudge along the shell.
            @channel.send_data "\n"
            @last_input = sent_nl_at
          end
        end

        !prompted?
      end

      reset_prompted
    end

    def sterilize(data)
      if @options[:filter_password]
        spwd = '*' * @options[:password].length
        data.gsub(@options[:password], spwd)
      else
        data
      end
    end

    def strip_ansi_escape(data)
      data
          .gsub(/\e\[(\d+;?)*[ABCDEFGHfu]/, "\n")   #   any of the "set cursor position" CSI commands.
          .gsub(/\e\[=?(\d+;?)*[A-Za-z]/,'')        #   \e[#;#;#A or \e[=#;#;#A  basically all the CSI commands except ...
          .gsub(/\e\[(\d+;"[^"]+";?)+p/, '')        #   \e[#;"A"p
          .gsub(/\e[NOc]./,'?')                     #   any of the alternate character set commands.
          .gsub(/\e[P_\]^X][^\e\a]*(\a|(\e\\))/,'') #   any string command
          .gsub(/[\x00\x08\x0B\x0C\x0E-\x1F]/, '')  #   any non-printable characters (notice \x0A (LF) and \x0D (CR) are left as is).
          .gsub("\t", ' ')                          #   turn tabs into spaces.
    end

    def sftp
      raise ConnectionClosed.new('Connection is closed.') unless @ssh
      @sftp ||= ::Net::SFTP.start(@options[:host], @options[:user], password: @options[:password])
    end

  end
end
