require 'fileutils'

module LetsencryptWebfaction
  class DomainValidator
    def initialize(domains, client, public_dirs)
      @domains = domains
      @client = client
      @public_dirs = public_dirs.map { |dir| File.expand_path(dir) }
    end

    def validate! # rubocop:disable Metrics/MethodLength
      write_files!

      challenges.map(&:request_validation).tap do |requests|
        next unless requests.any?(&:!)

        $stderr.puts 'Failed to request validations.'
        return false
      end

      10.times do
        break if no_challenges_pending?

        sleep(1)
        challenges.map(&:reload)
      end

      return true if all_challenges_valid?

      print_errors
      false
    end

    def order
      @order ||= @client.new_order(identifiers: @domains)
    end

    private

    def authorizations
      @authorizations ||= order.authorizations
    end

    def challenges
      @challenges ||= authorizations.map(&:http01)
    end

    def no_challenges_pending?
      challenges.none? { |challenge| challenge.status == 'pending' }
    end

    def all_challenges_valid?
      challenges.reject { |challenge| challenge.status == 'valid' }.empty?
    end

    def write_files!
      challenges.each do |challenge|
        @public_dirs.each do |public_dir|
          # Save the file. We'll create a public directory to serve it from, and we'll creating the challenge directory.
          FileUtils.mkdir_p(File.join(public_dir, File.dirname(challenge.filename)))

          # Then writing the file
          File.write(File.join(public_dir, challenge.filename), challenge.file_content)
        end
      end
    end

    def print_errors
      validations = authorizations.map(&:domain).zip(challenges)
      $stderr.puts 'Failed to verify statuses.'
      validations.each { |tuple| Validation.new(*tuple).print_error }
    end

    class Validation
      def initialize(domain, challenge)
        @domain = domain
        @challenge = challenge
      end

      def print_error # rubocop:disable Metrics/MethodLength
        case @challenge.status
        when 'valid'
          $stderr.puts "#{@domain}: Success"
        when 'invalid'
          $stderr.puts "#{@domain}: #{@challenge.error['detail']}"
          $stderr.puts "Make sure that you can access #{url}"
        when 'pending'
          $stderr.puts "#{@domain}: Still pending, but timed out"
        else
          $stderr.puts "#{@domain}: Unexpected authorization status #{@challenge.status}"
        end
      end

      def url
        "http://#{@domain}/#{@challenge.filename}"
      end
    end
  end
end
