# Eye, The Vulnerability Assessment Tool
# Author: [1hehaq]
# Version: 1.0

require 'dotenv/load'
require 'resolv'
require 'openai'
require 'timeout'
require 'artii'
require 'openssl'
require 'socket'
require 'net/ping'

artii = Artii::Base.new(font: 'fraktur')

eye_banner = "\n" + "\e[31m" + artii.asciify('Eye') + "\e[0m" + "\e[5m"

puts eye_banner

module Input
  def self.get_input
    Wizard.run
  end
end

module Wizard
  def self.run
    puts "\n\nLet's get started with the setup process."

    print "Enter the target IP or domain: " + "\e[0m"
    target = gets.chomp
    puts "Target set to: #{target}"

    print "Do you want to perform Subdomain Enumeration? (y/n): "
    subdomains_file = ask_for_file("subdomains")

    print "Do you want to perform URL Enumeration? (y/n): "
    urls_file = ask_for_file("URLs")

    ai_enabled = enable_ai_analysis?

    {
      target: target,
      subdomains_file: subdomains_file,
      urls_file: urls_file,
      ai_analysis: ai_enabled
    }
  end

  private

  def self.ask_for_file(type)
    answer = gets.chomp.downcase
    if answer == 'y'
      print "Enter the path to the #{type.downcase} wordlist file (or type 'default' for built-in wordlist): "
      file_path = gets.chomp
      file_path == 'default' ? nil : file_path
    end
  end

  def self.enable_ai_analysis?
    puts "Configure AI Analysis"
    puts "1. Enable AI-powered Report!"
    puts "2. Disable AI-powered Report!"
    print "Enter your choice (1-2): "
    ai_analysis = gets.chomp.to_i
    ai_analysis == 1
  end
end

module ActiveReconnaissance
  INBUILT_SUBDOMAINS = %w[
    www
    mail
    blog
    ftp
    api
    shop
    forum
    dev
    test
    login
    signup
    docs
    support
    news
    billing
    crm
    portal
    chat
    demo
    dashboard
    backup
    staging
    qa
    status
    marketing
    cdn
    assets
    app
    webmail
    smtp
    imap
    pop
    relay
    proxy
    vpn
    ldap
    ntp
    ssh
    git
    svn
    docker
    registry
    jenkins
    puppet
    ansible
    chef
    npm
    yum
    apt
    rsync
    scp
    sftp
    http
    https
    ftps
    dns
    dhcp
    snmp
    icmp
    telnet
    pop3
    irc
    tcp
    udp
    mysql
    postgres
    oracle
    mssql
    mongodb
    redis
    memcached
    elasticsearch
    couchbase
    cassandra
    couchdb
    rabbitmq
    activemq
    kafka
    zookeeper
    etcd
    consul
    nfs
    samba
    k8s
    pod
    namespace
    service
    deployment
    configmap
    secret
    cronjob
    job
    ingress
    serviceaccount
    role
    rolebinding
    clusterrole
    clusterrolebinding
    pv
    pvc
    storageclass
    statefulset
    daemonset
    networkpolicy
    poddisruptionbudget
    admin
    login
    api
    docs
    support
    http
    https
    ftp
    sftp
    mysql
    postgres
    oracle
    mssql
    mongodb
    redis
    memcached
    elasticsearch
    couchbase
    cassandra
    couchdb
    rabbitmq
    activemq
    kafka
    zookeeper
    etcd
    consul
    nfs
    samba
    k8s
    pod
    namespace
    service
    deployment
    configmap
    secret
    cronjob
    job
    ingress
    serviceaccount
    role
    rolebinding
    clusterrole
    clusterrolebinding
    pv
    pvc
    storageclass
    namespace
    configmap
    secret
    ingress
    service
    statefulset
    daemonset
    networkpolicy
    poddisruptionbudget
  ]

  INBUILT_URLS = %w[
    /login
    /signup
    /logout
    /account
    /profile
    /settings
    /preferences
    /notifications
    /help
    /contact
    /about
    /terms
    /privacy
    /faq
    /support
    /blog
    /news
    /articles
    /press
    /media
    /downloads
    /documentation
    /api
    /docs
    /examples
    /samples
    /tutorials
    /guides
    /learn
    /resources
    /forum
    /community
    /discussion
    /feedback
    /suggestions
    /survey
    /ideas
    /feature-request
    /bug-report
    /contact-us
    /submit-ticket
    /report-issue
    /submit-feedback
    /report-bug
    /live-chat
    /chat
    /contact-form
    /feedback-form
    /subscribe
    /unsubscribe
    /notifications
    /alerts
    /members
    /customers
    /users
    /staff
    /team
    /developers
    /partners
    /clients
    /customers
    /orders
    /billing
    /payments
    /invoices
    /transactions
    /shipping
    /returns
    /refunds
    /faq
    /help-center
    /customer-support
    /checkout
    /cart
    /store
    /shop
    /products
    /services
    /solutions
    /purchase
    /order-now
    /buy-now
    /add-to-cart
    /add-to-basket
    /checkout
    /basket
    /payment
    /proceed-to-checkout
  ]
  def self.subdomain_enumeration(target, subdomains_file)
    subdomains = []

    if subdomains_file && File.exist?(subdomains_file)
      File.readlines(subdomains_file).each do |line|
        subdomains << "#{line.chomp.strip}.#{target}"
      end
    else
      INBUILT_SUBDOMAINS.each { |word| subdomains << "#{word}.#{target}" }
    end

    valid_subdomains = subdomains.select { |subdomain| Resolv.getaddress(subdomain) rescue nil }
    valid_subdomains
  end

  def self.url_enumeration(url, urls_file)
    urls = []

    if urls_file && File.exist?(urls_file)
      File.readlines(urls_file).each { |line| urls << "#{url}/#{line.chomp.strip}" }
    else
      INBUILT_URLS.each { |word| urls << "#{url}/#{word}" }
    end

    urls
  end

  def self.port_scan(target, port)
    ping = Net::Ping::TCP.new(target, port)
    ping.ping?
  end
end

module SSLCertificateChecker
  def self.check_certificate(domain)
    context = OpenSSL::SSL::SSLContext.new
    sock = TCPSocket.new(domain, 443)
    ssl = OpenSSL::SSL::SSLSocket.new(sock, context)
    ssl.connect
    cert = OpenSSL::X509::Certificate.new(ssl.peer_cert)
    ssl.close
    sock.close

    {
      subject: cert.subject.to_s,
      issuer: cert.issuer.to_s,
      not_before: cert.not_before,
      not_after: cert.not_after
    }
  rescue OpenSSL::SSL::SSLError => e
    puts "Failed to retrieve SSL certificate for #{domain}: #{e.message}"
    nil
  rescue => e
    puts "An unexpected error occurred while checking the SSL certificate for #{domain}💀: #{e.message}"
    nil
  end
end

module Presentation
  def self.print_results(vulnerabilities, ssl_info, open_ports)
    puts "\nScan Results 📊:"
    if vulnerabilities.empty?
      puts "No vulnerabilities found ✅"
    else
      vulnerabilities.each do |vulnerability|
        puts "\n📛 Vulnerability Name: #{vulnerability[:name]}"
        puts "🐞 Vulnerability Type: #{vulnerability[:type]}"
        puts "📊 Severity: #{vulnerability[:severity]}"
        puts "📦 Description: #{vulnerability[:description]}"
        puts "📃 Recommendation: #{vulnerability[:recommendation]}"
        puts "🔒 Confidence: #{vulnerability[:confidence]}"
      end
    end

    unless ssl_info.nil?
      puts "\nSSL Certificate Information:"
      puts "Subject: #{ssl_info[:subject]}"
      puts "Issuer: #{ssl_info[:issuer]}"
      puts "Valid From: #{ssl_info[:not_before]}"
      puts "Valid To: #{ssl_info[:not_after]}"
    end

    unless open_ports.empty?
      puts "\nOpen Ports:"
      open_ports.each do |port|
        puts "Port #{port} is open"
      end
    end
  end
end

module AI
  def self.prioritize_vulnerabilities(configuration, vulnerabilities)
    ai_service = OpenAI::Client.new(access_token: 'your_api_key_here')
    sorted_vulnerabilities = vulnerabilities.sort_by do |vul|
      response = ai_service.completions(
        engine: "davinci",
        prompt: "Rate the severity of the vulnerability: #{vul[:name]}\n",
        max_tokens: 10
      )
      response['choices'][0]['text'].to_f
    rescue OpenAI::Error => e
      puts "An error occurred while prioritizing vulnerabilities 💀: #{e.message}"
      0.0
    end

    sorted_vulnerabilities.reverse
  end
end

def nmapr_scan(ipv4_target)
  ports = []
  (1..65535).each do |port|
    ports << port if ActiveReconnaissance.port_scan(ipv4_target, port)
  end
  ports
end


def main
  configuration = Input.get_input
  target = configuration[:target]

  puts "\nActive Reconnaissance 🔎:"

  begin
    open_ports = (1..65535).select { |port| ActiveReconnaissance.port_scan(target, port) }
  rescue StandardError => e
    puts "Error running port scan 💀: #{e.message}"
    return
  end

  begin
    ssl_info = SSLCertificateChecker.check_certificate(target)
  rescue StandardError => e
    puts "Error checking SSL certificate 💀: #{e.message}"
    return
  end

  puts "\nRunning the Evaluation Mode ⚙️: "


  if configuration[:ai_analysis]
    puts "Running AI analysis 🤖: "
    begin
      vulnerabilities = AI.prioritize_vulnerabilities(configuration, vulnerabilities)
    rescue StandardError => e
      puts "Error running AI analysis 💀: #{e.message}"
      return
    end
  end

  Presentation.print_results(vulnerabilities, ssl_info, open_ports)
end

# Begin the assessment
puts "\t\t\t\t👁️ by 1hehaq!" + "\e[25m" + "\e[32m"

main if __FILE__ == $0
