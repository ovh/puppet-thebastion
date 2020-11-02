require 'spec_helper'
require 'json'

describe 'thebastion::plugin' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      let :title do
        'myLittlePlugin'
      end

      let :pre_condition do
        [
          'include ::thebastion',
        ]
      end

      it { is_expected.to compile.with_all_deps }
      it { is_expected.to contain_file('/etc/bastion') }
      it { is_expected.to contain_concat('/etc/bastion/plugin.myLittlePlugin.conf') }
      it { is_expected.to contain_concat__fragment('thebastion-plugin-myLittlePlugin-header').with_content(%r{^#}) }
      it { is_expected.to contain_concat__fragment('thebastion-plugin-myLittlePlugin-conf') }
      it { is_expected.to create_class('thebastion') }
      it { is_expected.to contain_class('thebastion::config') }

      context 'Valid configuration validation' do
        let(:params) do
          {
            configuration: {
              'disabled'     => true,
              'mfa_required' => 'any',
            },
          }
        end

        it 'tests valid parameters input' do
          parsed = JSON.parse(catalogue.resource('concat::fragment', 'thebastion-plugin-myLittlePlugin-conf').send(:parameters)[:content])
          expect(parsed['disabled']).to be true
          expect(parsed['mfa_required']).to eq('any')
        end
      end

      context 'Invalid disabled conf input' do
        let(:params) do
          {
            configuration: {
              'disabled' => 'yes',
            },
          }
        end

        it { is_expected.to compile.and_raise_error(%r{disabled configuration in a plugin must be Boolean.}) }
      end
      context 'Invalid mfa_required conf input' do
        let(:params) do
          {
            configuration: {
              'mfa_required' => 'yes',
            },
          }
        end

        it { is_expected.to compile.and_raise_error(%r{mfa_required configuration in a plugin must have value in password totp any none.}) }
      end
    end
  end
end
