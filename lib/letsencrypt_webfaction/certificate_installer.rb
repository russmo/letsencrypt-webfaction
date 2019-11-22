require 'xmlrpc/client'

module LetsencryptWebfaction
  class CertificateInstaller
    def initialize(cert_name, certificate, csr_private_key, credentials, full_chain = true)
      @cert_name = cert_name
      @certificate = certificate
      @csr_private_key = csr_private_key
      @credentials = credentials
      @full_chain = full_chain
    end

    def install!
      cert_list = @credentials.call('list_certificates')
      action = if cert_list.find { |cert| cert['name'] == @cert_name }
                 'update_certificate'
               else
                 'create_certificate'
               end
      if @full_chain
        # Install single cert file with entire chain appended, this is what 
        # ACME v2 client returns directly.  It appears Webfaction can handle
        # this full bundle cert just fine.
        @credentials.call(action, @cert_name, @certificate, @csr_private_key.to_pem)
      else
        # 
        cert = OpenSSL::X509::Certificate.new(@certificate).to_pem
        extra_chain = @certificate.sub(cert, '')
        @credentials.call(action, @cert_name, cert, @csr_private_key.to_pem, extra_chain)
      end

      true
    end
  end
end
