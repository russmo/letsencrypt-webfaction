# LetsEncrypt WebFaction

LetsEncrypt utility client for WebFaction hosts.

This tool simplifies the manual process of using LetsEncrypt on WebFaction hosts. It can be added to the Cron scheduled task runner where it will validate your domains automatically, place the generated certificates in a common folder, and then email the WebFaction Support team to request installation, also notifying you.

[![Build Status](https://travis-ci.org/will-in-wi/letsencrypt-webfaction.svg?branch=master)](https://travis-ci.org/will-in-wi/letsencrypt-webfaction)

[![Gem Version](https://badge.fury.io/rb/letsencrypt_webfaction.svg)](https://badge.fury.io/rb/letsencrypt_webfaction)

[![Code Climate](https://codeclimate.com/github/will-in-wi/letsencrypt-webfaction/badges/gpa.svg)](https://codeclimate.com/github/will-in-wi/letsencrypt-webfaction)

*Note: if you find this useful and are setting up a new account, you can support me a little by using [my WebFaction affiliate link](https://www.webfaction.com/?aid=49923). I think I get a 10% referal bonus from whatever you spend at WebFaction. Thanks!*

## Why not Certbot?

[Certbot](https://certbot.eff.org/) is the "official" (in that it was the first and to some extent reference client) Let's Encrypt client. Let's Encrypt decided to focus Certbot on a particular use case, namely the configuration of servers which are directly facing the internet and can have the Certbot application run as root. For other use cases, they encourage the implementation of other clients tailored to different cases. This has spawned a wide variety of alternative implementations.

LetsEncrypt WebFaction is just such an alternative implementation. It was built because the WebFaction use case does not fit in the Certbot preconditions, namely that users don't have root access to change the frontend Nginx server configuration. WebFaction thus far requires that we place the certificate and private key somewhere on the server and then submit a ticket to install the certificate. This is exactly the workflow that is being automated.

Certbot could probably be used in "manual" mode to create the certificate on disk, and then something else wired up to make the certificate installation request. For various reasons, I decided not to do this. If someone creates instructions to do this, I'd be happy to link to it from [the wiki](https://github.com/will-in-wi/letsencrypt-webfaction/wiki).

## Prerequisite topics

Below are a list of server administration topics that it is assumed you know in order to follow the installation and setup instructions. If you find something in the readme that is unclear to you, please open a ticket and I'll try to improve the documentation!

### Cron

Cron is an application which will execute commands on a defined schedule. WebFaction has [some good documentation on how to use it](https://docs.webfaction.com/software/general.html#scheduling-tasks-with-cron).

### SSH

All of the commands listed below (unless specified otherwise) are run in an SSH session on the server. Again, WebFaction has written a [splendid little tutorial on how to get this working](https://docs.webfaction.com/user-guide/access.html#ssh).

### SFTP

If you're not happy navigating around your server's folders and files through SSH, you might find some of this process easier if you access your server with an FTP client over Secure FTP. WebFaction [also has this covered](https://docs.webfaction.com/user-guide/access.html#connecting-with-ftp).

## Installation

This utility works on [CentOS 6 and 7 boxes](https://docs.webfaction.com/user-guide/server.html#finding-your-server-s-operating-system). The CentOS 5 systems do not have a new enough OpenSSL to include the algorithms required. You may be able to make this work using rbenv and compiling openssl yourself. A tutorial for CentOS 5 is available here: https://github.com/will-in-wi/letsencrypt-webfaction/wiki/Install-custom-OpenSSL-and-Ruby-on-CentOS-5-host

All places where you need to substitute a value specific to your setup will be denoted with square brackets, e.g. [yourdomain.com]. There are cases where shell variables are used, such as `$HOME`. These should be typed verbatim.

You can install LetsEncrypt WebFaction using the system Ruby or using RBEnv.

### System Ruby

This is the simpler method and is preferred.

Run the following command in an SSH session to install the letsencrypt_webfaction package via the [RubyGems package management site](https://rubygems.org/gems/letsencrypt_webfaction):

```sh
GEM_HOME=$HOME/.letsencrypt_webfaction/gems RUBYLIB=$GEM_HOME/lib gem2.2 install letsencrypt_webfaction
```

Add the following to `~/.bash_profile` (using, for example, an FTP client or your favorite text editor):

```sh
function letsencrypt_webfaction {
    PATH=$PATH:$GEM_HOME/bin GEM_HOME=$HOME/.letsencrypt_webfaction/gems RUBYLIB=$GEM_HOME/lib ruby2.2 $HOME/.letsencrypt_webfaction/gems/bin/letsencrypt_webfaction $*
}
```
This will simplify the running of the LetsEncrypt WebFaction command, by setting some variables in advance.

After saving `~/.bash_profile`, run the command `source $HOME/.bash_profile` to apply the new settings.

Now, you are ready to run `letsencrypt_webfaction` from your SSH session to get certificates. See below for usage. 

### RBEnv

This method is useful if you are already using RBEnv to manage Ruby, or if you are already a Ruby developer. If neither of these cases are true, just use the system Ruby method.

Follow the instructions to [set up RBEnv](https://github.com/rbenv/rbenv) and [Ruby Build](https://github.com/rbenv/ruby-build#readme) on your WebFaction server.

Once you have done so, install Ruby 2.1+ (probably 2.3.0 at time of writing). Then set the local Ruby and install the Gem. Finally unset the local Ruby so that you don't run into problems.

    $ rbenv install 2.3.0 # Installs Ruby 2.3.0
    $ rbenv local 2.3.0 # Sets Ruby 2.3.0 as the default version in the current folder.
    $ gem install letsencrypt_webfaction # Installs this utility from RubyGems.
    $ rbenv rehash # Makes RBenv aware of the letsencrypt_webfaction utility.
    $ rm .ruby-version # Unsets Ruby 2.3.0 as the default version in the current folder.

## Usage

### Syntax

The syntax of the letsencrypt_webfaction command is as follows:

    $ letsencrypt_webfaction --account_email <email-address> --domains <domain[,domain[,domain...]]> --public <server-folder>

    

### Options:

* `--account_email`

    Your WebFaction contact email address.

* `--domains` 
    
    The domains for which you want to create certificates, separated by commas (with no spaces). The domains must be served from the same folder. There is one certificate per webapp, regardless of how many domains are served from it.

* `--public`

    A folder which is directly served at `http://[yourdomain.com]/` into which the ACME verification files can be placed.

    In the case of a PHP site, such as Drupal or Wordpress, look for the folder with `index.php` in it. This is usually in `/home/[myuser]/webapps/[yourapp/]`.

    In the case of a Rails app, look for a folder called `public/`. If you are deploying your app with Capistrano, this could show up in `/home/myuser/webapps/[yourapp]/current/public/`. 

If you have several webapps, then you will need to issue the command several times. The command can be run from any folder. 

### Example
Here is a basic example which issues one certificate for both yourdomain.com and www.yourdomain.com, both of which are served by `~/webapps/yourapp/wordpress` and your WebFaction contact email address is you@youremail.com. This assumes that both yourdomain.com and www.yourdomain.com are served from the same folder. 

    $ letsencrypt_webfaction --account_email you@youremail.com --domains yourdomain.com,www.yourdomain.com --public ~/webapps/yourapp/wordpress/

### Testing

To test certificate issuance, consider using the [LetsEncrypt staging server](https://community.letsencrypt.org/t/testing-against-the-lets-encrypt-staging-environment/6763). This doesn't have the rate limit of 5 certs per domain every 7 days. You can add the `--endpoint https://acme-staging.api.letsencrypt.org/` parameter to the `letsencrypt_webfaction` command to do so.

### Operation

When letsencrypt_webfaction runs, it places verification files into the public directory specified, validates the domains with LetsEncrypt, and then dumps the signed certificate and private key into an output folder. By default, the output folder is `~/le_certs/`, inside which it will create `[domain_name]/[timestamp]/`.

After this is done, the utility will email the certificate installation request to WebFaction Support, copying you.

To quickly get a list of parameters and help for each, you can run:

    $ letsencrypt_webfaction --help

Once you have the certificate installed and working, you will probably want to redirect the HTTP version of your site to the HTTPS version. WebFaction has [documentation describing how to do this](https://docs.webfaction.com/software/static.html#static-redirecting-from-http-to-https).

### Cron usage

Normally, you will run the script manually once to get the certificate, and then you will use Cron to automate future certificate renewal.

Your Cron task could look something like:

    # System Ruby Installation
    0 4 1 */2 *     PATH=$PATH:$GEM_HOME/bin GEM_HOME=$HOME/.letsencrypt_webfaction/gems RUBYLIB=$GEM_HOME/lib ruby2.2 $HOME/.letsencrypt_webfaction/gems/bin/letsencrypt_webfaction --account_email [you@youremail.com] --domains [yourdomain.com,www.yourdomain.com] --public ~/webapps/[yourapp/your_public_html]/
    # RBEnv Installation
    0 4 1 */2 *     RBENV_ROOT=~/.rbenv RBENV_VERSION=2.3.0 ~/.rbenv/bin/rbenv exec letsencrypt_webfaction --account_email [you@youremail.com] --domains [yourdomain.com,www.yourdomain.com] --public ~/webapps/[yourapp/your_public_html]/

This [would run](http://crontab.guru/#0_4_1_*/2_*) at 4 a.m. on the first day of January, March, May, July, September, and November. Certificates expire three months after issuance, so modify as desired (for example, you may want to run the task every two months initially, to be sure that everything is working before extending the period). Change the date of the Cron task so that WebFaction staff don't simultaneously receive all certificate change requests on the first day of the month.

If you have more than one Cron task running like this, you may want to set the environment variables at the top of the file, and create a config file containing the contact information.

## Upgrading

While WebFaction staff maintain your standard server software, the support team will not upgrade your installation of LetsEncrypt WebFaction. You won't usually need to do this unless you have an issue but, as is good practice with most software, it's best kept up to date.

You can find the current version by running `letsencrypt_webfaction --version`. Sort of. In versions >= 1.1.4, this will work. In older versions, this will just print `letsencrypt_webfaction: version unknown` due to an oversight on my part. So if you get the latter output, just upgrade.

[The changelog](./CHANGELOG.md) describes changes from version to version.

LetsEncrypt WebFaction follows [Semantic Versioning](http://semver.org/). In a nutshell, a version number such as `1.2.3` is divided as `major.minor.patch`. When the major version is incremented, you will probably have to change something about the configuration to make it work. The changelog will let you know what changes you need to make. When the minor version is incremented, there are new features but existing features haven't changed. If the patch version is incremented, the changes are all under the hood and shouldn't change or add any existing features.

TL;DR: Be careful with major version upgrades and you should be fine with upgrading to minor or patch releases.

To upgrade, run one of the following two commands to fetch and install the newest version from RubyGems:

```sh
# For system Ruby:
GEM_HOME=$HOME/.letsencrypt_webfaction/gems RUBYLIB=$GEM_HOME/lib gem2.2 install letsencrypt_webfaction

# For RBenv
RBENV_VERSION=2.3.0 gem install letsencrypt_webfaction
```

### More detailed examples

Default parameters can be found in [config.defaults.yml](./config.defaults.yml). All of the parameters can be overridden by passing another config file, arguments to the executable, or both. If a config file and arguments are passed, they will be interleaved with the arguments having precedence.

A config file needs to be in YAML format and have a subset of the keys in [config.defaults.yml](./config.defaults.yml). If you use a config file, you add the `--config [./myconfig.yml]` parameter to the letsencrypt_webfaction command.

This allows you to set up a Cron task for multiple sites with the defaults for all of them (such as your email address) in a config file, and site specific directives in the command. For example:

    $ letsencrypt_webfaction --config [~/le_config.yml] --domains [yourdomain.com,www.yourdomain.com] --public ~/webapps/[yourapp/your_public_html/]

This could be run automatically every two months.

### Custom email configuration

If you use a WebFaction email address, the process of sending emails to WebFaction Support should work just fine. In some cases, particularly in the case of Gmail, you may need to override the default usage of Sendmail and use SMTP. You can create a custom configuration file as described above (passed using `--config`) and add the below custom configuration in order to accomplish this.

A Gmail example might be:

```yaml
email_configuration:
  :via: 'smtp'
  :via_options:
    :address: 'smtp.gmail.com'
    :port: '587'
    :enable_starttls_auto: true
    :user_name: '[you@gmail.com]'
    :password: '[password_see_note]'
    :authentication: 'plain'
    :domain: 'localhost.localdomain' # the HELO domain provided by the client to the server
```

See this [project's GitHub wiki](https://github.com/will-in-wi/letsencrypt-webfaction/wiki) for additional Gmail specific notes.

For all possible options, see [the Pony configuration](https://github.com/benprew/pony).

## Development

If you are interested in contributing to this project with new code or bugfixes, welcome!

To run the script directly from the repository, use:

    $ ruby -Ilib exe/letsencrypt_webfaction

The note above about the Let's Encrypt stage server is very helpful when developing.

You will probably also want to use the argument `--support_email ""` which will keep support from actually being contacted. Alternately, set the `support_email` address to be yourself.

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bin/rake install`. To release a new version, update the version number in `lib/letsencrypt_webfaction.rb`, and then run `bin/rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org). This project uses [Semantic Versioning](http://semver.org/).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/will-in-wi/letsencrypt-webfaction
