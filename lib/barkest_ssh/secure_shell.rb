
require 'net/ssh'

module BarkestSsh

  ##
  # The SecureShell class is used to run an SSH session with a local or remote host.
  #
  # This is a wrapper for Net::SSH that starts a shell session and executes a block.
  # All of the output from the session is cached for later use as needed.
  #
  class SecureShell

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
          prompt: options[:prompt].blank? ? '~~#' : options[:prompt]
      }

      raise ArgumentError.new('Missing block.') unless block_given?
      raise ArgumentError.new('Missing host.') if @options[:host].blank?
      raise ArgumentError.new('Missing user.') if @options[:user].blank?
      raise ArgumentError.new('Missing password.') if @options[:password].blank?
      raise ArgumentError.new('Missing prompt.') if @options[:prompt].blank?

      @options[:prompt] = @options[:prompt]
                              .gsub('!', '#')
                              .gsub('$', '#')
                              .gsub('\\', '.')
                              .gsub('/', '.')
                              .gsub('"', '-')
                              .gsub('\'', '-')

      Net::SSH.start(
          @options[:host],
          @options.delete(:user),
          password: @options.delete(:password),
          port: @options[:port]
      ) do |ssh|
        ssh.open_channel do |channel|
          channel.request_pty do |channel, success|
            raise StandardError.new('Failed to request PTY.') unless success
            channel.send_channel_request('shell') do |channel, success|
              raise StandardError.new('Failed to start shell.') unless success

              # cache the channel pointer and start buffering the input.
              @channel = channel
              buffer_input

              # give the shell a chance to catch up and initialize fully.
              sleep 0.25

              # set the shell prompt so that we can determine when processes end.
              exec "PS1=\"#{@options[:prompt]}\""

              block.call(self)

              # send the exit command and remove the channel pointer.
              quit
              @channel = nil
            end
          end
          channel.wait
        end
      end
    end

    ##
    # Executes a command during the shell session.
    #
    # If called outside of the +new+ block, this will raise an error.
    #
    # The +command+ is the command to execute in the shell.
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
    def exec(command, &block)
      raise StandardError.new('Connection is closed.') unless @channel

      push_buffer # store the current buffer and start a fresh buffer

      # buffer while also passing data to the supplied block.
      if block_given?
        buffer_input &block
      end

      # send the command and wait for the prompt to return.
      @channel.send_data command + "\n"
      wait_for_prompt

      # return buffering to normal.
      if block_given?
        buffer_input
      end

      # get the output from the command, minus the trailing prompt.
      ret = combined_output[0...-(@options[:prompt].length)].strip

      # restore the original buffer and merge the output from the command.
      pop_merge_buffer

      # return the output from the command starting with the second line.
      # the first line is the command sent to the shell.
      # We also check for those rare times when a prompt manages to sneak in, trimming them off the front as well.
      result_cmd,_,result_data = ret.partition("\n")
      cmd_with_prompt = @options[:prompt] + command
      until result_cmd == command || result_cmd == cmd_with_prompt || result_data.blank?
        result_cmd,_,result_data = result_data.partition("\n")
      end
      result_data
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
      raise StandardError.new('Connection is closed.') unless @channel
      @channel.send_data("exit\n")
      @channel.wait
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

    def append_stdout(data, &block)
      # If the prompt appears in the output, then the program must have returned control to the shell.
      # It may continue running in the background, but the shell is now ready for more input.
      # And if the the program decides to spit out more data, we don't lose our shell and end up in
      # a locked state.
      set_prompted if data.include?(@options[:prompt])

      # Combined output gets the prompts,
      # but stdout will be without prompts.
      # All line endings are converted to LF.
      data = data.gsub("\r\n", "\n").gsub("\r", "\n")
      for_stdout = if data[-(@options[:prompt].length)..-1] == @options[:prompt]
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
      # All line endings are converted to LF.
      data = data.gsub("\r\n", "\n").gsub("\r", "\n")

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
      raise StandardError.new('Connection is closed.') unless @channel
      block ||= Proc.new { }
      @channel.on_data do |_, data|
        append_stdout strip_ansi_escape(data), &block
      end
      @channel.on_extended_data do |_, type, data|
        if type == 1
          append_stderr strip_ansi_escap(data), &block
        end
      end
    end

    def wait_for_prompt
      raise StandardError.new('Connection is closed.') unless @channel
      @channel.connection.loop do
        !prompted?
      end
      reset_prompted
    end

    def strip_ansi_escape(data)
      data
          .gsub(/\e\[=?(\d+;?)*[A-Za-z]/,'')    #   \e[#;#;#A or \e[=#;#;#A
          .gsub(/\e\[(\d+;"[^"]+";?)+p/, '')    #   \e[#;"A"p
    end

  end
end
