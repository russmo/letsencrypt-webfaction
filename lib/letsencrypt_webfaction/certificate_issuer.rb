require 'acme-client'
require 'letsencrypt_webfaction/domain_validator'
require 'letsencrypt_webfaction/certificate_installer'
require 'openssl'

module LetsencryptWebfaction
  class CertificateIssuer
    def initialize(certificate:, api_credentials:, client:)
      @cert_config = certificate
      @api_credentials = api_credentials
      @client = client
    end

    def call
      # Validate the domains.
      return unless validator.validate!

      # Write the obtained certificates.
      certificate_installer.install!

      output_success_help
    end

    private

    def validator
      @_validator ||= LetsencryptWebfaction::DomainValidator.new @cert_config.domains, @client, @cert_config.public_dirs
    end

    def order
      validator.order
    end

    def certificate_installer
      @_certificate_installer ||= LetsencryptWebfaction::CertificateInstaller.new(@cert_config.cert_name, certificate, @csr_private_key, @api_credentials, @cert_config.full_chain)
    end

    def certificate
      # We can now request a certificate, you can pass anything that returns
      # a valid DER encoded CSR when calling to_der on it, for example a
      # OpenSSL::X509::Request too.
      @_certificate ||= begin
        order.finalize(csr: csr)
        while order.status == 'processing'
          sleep(1)
          order.reload
        end
        order.certificate # => PEM-formatted certificate
      end
    end

    def csr
      # We're going to need a certificate signing request. If not explicitly
      # specified, the first name listed becomes the common name.
      @csr_private_key = OpenSSL::PKey::RSA.new(4096)
      @_csr ||= Acme::Client::CertificateRequest.new(private_key: @csr_private_key, names: @cert_config.domains)
    end

    def output_success_help
      Out.puts 'Your new certificate is now created and installed.'
      Out.puts "You will need to change your application to use the #{@cert_config.cert_name} certificate."
      Out.puts 'Add the `--quiet` parameter in your cron task to remove this message.'
    end
  end
end
