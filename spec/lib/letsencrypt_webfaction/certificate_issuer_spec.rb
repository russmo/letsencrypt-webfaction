require 'letsencrypt_webfaction/certificate_issuer'
require 'letsencrypt_webfaction/webfaction_api_credentials'
require 'letsencrypt_webfaction/options/certificate'

module LetsencryptWebfaction
  RSpec.describe CertificateIssuer do
    let(:cert_config) { Options::Certificate.new('domains' => 'test.example.com') }
    let(:api_credentials) do
      instance_double('LetsencryptWebfaction::WebfactionApiCredentials').tap do |creds|
        allow(creds).to receive(:call).and_return({}, nil)
      end
    end
    let(:challenge) { instance_double('Acme::Client::Resources::Challenges::HTTP01', request_validation: true, status: 'valid') }
    let(:authorization) { instance_double('Acme::Client::Resources::Authorization', http01: challenge) }
    let(:order) { instance_double(Acme::Client::Resources::Order, authorizations: [authorization]) }
    let(:validator) { instance_double(LetsencryptWebfaction::DomainValidator, validate!: true) }
    let(:installer) { instance_double(LetsencryptWebfaction::CertificateInstaller, install!: true) }
    let(:client) { instance_double('Acme::Client', new_order: order) }
    let(:myissuer) { instance_double(LetsencryptWebfaction::CertificateIssuer, validator: validator, certificate_installer: installer) }
    

    before :each do
      allow(LetsencryptWebfaction::DomainValidator).to receive(:new) { validator }
      allow(LetsencryptWebfaction::CertificateInstaller).to receive(:new) { installer }
    end


    describe '#call' do

      it 'validates and installs' do
        issuer = LetsencryptWebfaction::CertificateIssuer.new(certificate: cert_config, api_credentials: api_credentials, client: client)
        subject { issuer.call }

        expect { subject }.to output(/Your new certificate is now created and installed/).to_stdout
      end
    end
  end
end
