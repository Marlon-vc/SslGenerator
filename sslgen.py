import getopt
import subprocess
import traceback
import sys
import time
from datetime import datetime
from os import path

from selenium.webdriver import Firefox
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support import expected_conditions as ec
from selenium.webdriver.support.ui import WebDriverWait


class SslGen:
    def __init__(self, args, headless=True):
        self.email = ''
        self.domains = ''
        self.output_dir = ''
        self.cert_file = False
        self.generate_files = False

        # Validate params
        self.validate_params(args)

        # Init browser
        opts = Options()
        opts.headless = headless
        self.browser = Firefox(options=opts)
        self.browser.implicitly_wait(10)
        self.browser.get('https://gethttpsforfree.com/')

        # Needed for filling field 1
        time.sleep(2)

        # Steps
        try:
            self.account_info()
            self.csr()
            self.sign_api_requests()
            self.verify_ownership()
            self.install_cert()
        except Exception:
            exception = traceback.format_exc()
            self.write_log(exception)
            sys.stderr.write('An error ocurred while executing the script. See crash log for more information.')
            sys.stderr.flush()
        self.browser.close()

    def write_log(self, stacktrace):
        today = datetime.now()
        filename = today.strftime('%m-%d-%y-%H:%M') + '.log'
        with open(self.output_dir + filename, 'a') as log:
            log.write(stacktrace)
            log.write('\n')

    def validate_params(self, argv):
        """Validate input parameters"""
        try:
            opts, args = getopt.getopt(argv, "hfge:d:o:",
                                       ['email=', 'domains=', 'output=', 'challenge-files', 'certificate-file'])
        except getopt.GetoptError:
            print('usage: sslgen.py [fgo] -e <email> -d <domains>')
            sys.exit(2)

        for opt, arg in opts:
            if opt == '-h':
                info = 'SSL Generator v1.0\n' + \
                       '\nusage: sslgen.py [fgo] -e <email> -d <domains>\n' + \
                       '\nOptional parameters:\n' + \
                       '-f --challenge-files:   Generate challenge files instead of printing content to console.\n' + \
                       '-g --certificate-file:  Generate certificate file instead of printint content to console.\n' + \
                       '-o --output:            Specify output directory for generated files.\n'
                print(info)
                sys.exit()
            elif opt in ('-e', '--email'):
                self.email = arg
            elif opt in ('-d', '--domains'):
                domains_list = str(arg).split(sep=',')
                self.domains = ','.join(['DNS:' + domain for domain in domains_list])
            elif opt in ('-f', '--challenge-files'):
                self.generate_files = True
            elif opt in ('-g', '--certificate-file'):
                self.cert_file = True
            elif opt in ('-o', '--output'):
                arg = path.expanduser(arg)
                if path.exists(arg) and path.isdir(arg):
                    if arg.endswith('/'):
                        self.output_dir = arg
                    else:
                        self.output_dir = arg + '/'
                else:
                    sys.stderr.write('Output path is not valid.')
                    sys.stderr.flush()
                    sys.exit(1)

    def get_element_by_id(self, element_id):
        return WebDriverWait(self.browser, 30).until(
            ec.element_to_be_clickable((By.ID, element_id)))

    def write_field(self, field_id: str, value: str, submit=True):
        field = self.get_element_by_id(field_id)
        field.send_keys(value)
        if submit:
            field.submit()

    def read_field(self, field_id) -> str:
        field = self.get_element_by_id(field_id)
        return field.get_attribute('value')

    @staticmethod
    def abort_if_err(error, code):
        if code != 0:
            sys.stderr.write(error)
            sys.stderr.flush()
            sys.exit(code)

    def read_exec(self, cmd_id, output_id, submit=True):
        cmd = self.read_field(cmd_id)
        output, error, code = execute(cmd)
        self.abort_if_err(error, code)
        self.write_field(output_id, get_hex(output), submit=submit)

    def read_exec_in(self, container_id, cmd_selector, output_selector, submit=True):
        field_cmd = self.get_in(container_id, cmd_selector, multiple=False)
        field_output = self.get_in(container_id, output_selector, multiple=False)
        cmd = field_cmd.get_attribute('value')
        output, error, code = execute(cmd)
        self.abort_if_err(error, code)
        field_output.send_keys(get_hex(output))
        if submit:
            field_output.submit()

    def get_in(self, container_id, selector, multiple=True):
        full_selector = f'#{container_id} {selector}'
        if multiple:
            return WebDriverWait(self.browser, 30).until(
                ec.visibility_of_all_elements_located((By.CSS_SELECTOR, full_selector)))
        else:
            return WebDriverWait(self.browser, 30).until(
                ec.element_to_be_clickable((By.CSS_SELECTOR, full_selector)))

    def account_info(self):
        print('Step 1: Account Info')

        # set admin email
        self.write_field('email', self.email)

        # generate account.key if not exists
        if not path.exists(self.output_dir + 'account.key'):
            with open(self.output_dir + 'account.key', 'w') as account_file:
                output, error, code = execute('openssl genrsa 4096')
                self.abort_if_err(error, code)
                account_file.write(output)

        # write public account.key
        pubkey, error, code = execute('openssl rsa -in account.key -pubout')
        self.abort_if_err(error, code)
        self.write_field('pubkey', pubkey)

    def csr(self):
        print('Step 2: Certificate Signing Request')

        # generate domain.key if not exists
        exists = path.exists(self.output_dir + 'domain.key')
        use_existing = False

        if exists:
            use_existing = question('domain.key exists, use existing?')

        if (not exists) or (exists and not use_existing):
            with open(self.output_dir + 'domain.key', 'w') as domain_file:
                output, error, code = execute('openssl genrsa 4096')
                self.abort_if_err(error, code)
                domain_file.write(output)
        elif (not exists) and (not use_existing):
            print('Aborting...')
            sys.exit()

        # generate csr
        csr, error, code = execute('openssl req -new -sha256 -key domain.key -subj "/"' +
                                   ' -reqexts SAN -config <(cat /etc/ssl/openssl.cnf' +
                                   f' <(printf "\n[SAN]\nsubjectAltName={self.domains}"))')
        self.abort_if_err(error, code)

        # set csr
        self.write_field('csr', csr)

    def sign_api_requests(self):
        print('Step 3: Sign API Requests')

        self.read_exec('registration_sig_cmd', 'registration_sig')
        self.read_exec('update_sig_cmd', 'update_sig')
        self.read_exec('order_sig_cmd', 'order_sig')

    def verify_ownership(self):
        print('Step 4: Verify Ownership')

        section = self.get_element_by_id('auths')
        challenges = self.get_in(section.get_attribute('id'), '> div')
        challenges_count = len(challenges)

        for challenge in challenges:
            i = challenges.index(challenge) + 1
            print(f'\n### Challenge {i}/{challenges_count} ###')
            challenge_id = challenge.get_attribute('id')
            self.read_exec(challenge_id[5:] + '_auth_sig_cmd', challenge_id[5:] + '_auth_sig')

            # change tab (optional)
            self.get_in(challenge_id, 'label.challenge_file', multiple=False).click()

            # file data
            file_url: str = self.get_in(challenge_id, '.file_url', multiple=False).get_attribute('value')
            file_data: str = self.get_in(challenge_id, '.file_data', multiple=False).get_attribute('value')
            serving_file = self.get_in(challenge_id, '.confirm_file_submit', multiple=False)

            if self.generate_files:
                index = file_url.rfind('/')
                file_name = file_url[index + 1:]
                url = file_url[:index]
                with open(self.output_dir + file_name, 'w') as file:
                    file.write(file_data)
                print(f'\nUpload file: {file_name}\nto: {url}')
            else:
                print(f'\nIn this url:\n{file_url}')
                print(f'\nServe this content:\n{file_data}')

            input('\nPress enter to continue...')
            serving_file.submit()

            self.read_exec_in(challenge_id, '.file_sig_cmd', '.file_sig')
            self.read_exec_in(challenge_id, '.recheck_auth_file_sig_cmd', '.recheck_auth_file_sig')

        # finalize order
        self.read_exec('finalize_sig_cmd', 'finalize_sig')
        # check generation status
        self.read_exec('recheck_order_sig_cmd', 'recheck_order_sig')
        # retrieve generated certificate
        self.read_exec('cert_sig_cmd', 'cert_sig')

    def install_cert(self):
        print('Step 5: Install Certificate')

        # retrieve certificate
        data = self.read_field('crt').split("\n\n")

        if self.cert_file:
            with open(self.output_dir + 'cert.key', 'w') as cert_outfile, \
                    open(self.output_dir + 'cabundle.key', 'w') as cabundle_outfile:
                cert_outfile.write(data[0])
                cabundle_outfile.write(data[1])
                print('\nHint: private key is domain.key content')
                print('\nCertificate generated successfully')
        else:
            print(f'\nCERTIFICATE\n{data[0]}')

            with open(self.output_dir + 'domain.key', 'r') as domain_key:
                print(f'\nPRIVATE KEY\n{domain_key.read()}')

            print(f'\nCABUNDLE\n{data[1]}')


def question(q: str):
    result = input(q + ' Y/N: ')
    return result in ['y', 'Y', 's', 'S']


def execute(cmd):
    """Execute a command and returns output"""
    command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    (output, error) = command.communicate()
    command.wait(5)
    return output, error, command.returncode


def get_hex(output: str):
    i = output.index('(stdin)= ')
    return output[i + 9:]


if __name__ == '__main__':
    SslGen(sys.argv[1:])
