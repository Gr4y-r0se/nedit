['faraday','erb','json','colorize','optimist'].each(&method(:require))

require_relative 'modules/csv'
require_relative 'modules/targets'
require_relative 'modules/hostnames'
require_relative 'modules/ports'
require_relative 'modules/edit'
require_relative 'modules/info'
require_relative 'modules/online'
require_relative 'modules/scope'
require_relative 'modules/logs'
require_relative 'modules/scan'


#Parse commands, and display banner

opts = Optimist::options do
banner File.read('modules/banner.txt')
  opt :help, "Print this help message", :default => false
  opt :csv, "Nessus CSV Output - ITHC report annexe compatible", :default => false
  opt :targets, "Outputs the list of targets in the file", :default => false
  opt :hosts, "Outputs the list of targets and their hostnames (if availble)", :default => false
  opt :ports, "Outputs the list of targets and all the ports detected on that target", :default => false
  opt :edit, "Opens edit mode (type exit to close)", :default => false
  opt :online, "Shows all targets and if they are online or not", :default => false 
  opt :scope, "Generate a BurpSuite scope file based off of a nessus file"
  opt :logs, "Generates a log file for an infra assessment", :default => false
  opt :info, "Removes the informational findings from nessus files", :default => false 
  opt :web_scan, "Performs additional active web checks on in-scope URLs", :default => false
  opt :file, "Specify the nessus file\n\n ", :type => String
end

# Ensure mandatory parameters are present and Collisions don't happen 
Optimist::die :file, "- that file doesn't exist :).".red if !opts[:file] or File.file?(opts[:file]) == false

filename_ = File.expand_path(opts[:file])

if opts[:info] then 
  info(filename_) 
  puts "\n\n====Info Removal====\nNessus file has been updated and is here: #{filename_}"
end

if opts[:online] then 
  you_up = online(filename_) 
  puts "\n\n====Online====\n\n"
  you_up.each do |i|
    puts i
  end
end

if opts[:edit] then edit_mode(filename_) end

if opts[:csv] then 
  filename = csv(filename_) 
  puts "\n\n====CSV Output====\nCSV file has been created and is here: #{filename}"
end

if opts[:logs] then 
  filename = logs(filename_) 
  puts "\n\n====Logs Output====\nLog file has been created and is here: #{filename}"
end


####Deals with the target printing

if opts[:targets] then 
  targets_ = targets(filename_) 
  puts "\n\n====Targets====\n\n"
  targets_.each do |i| 
    puts i
  end
else
  targets_ = []
end

####Deals with the hostname printing

if opts[:hosts] then 
  hosts = hostnames(filename_) 
  puts "\n\n====Hostnames====\n\n"
  hosts.each do |i| 
    puts i 
  end
else
  hosts = []
end

####Deals with the port printing

if opts[:ports] then 
  open_ports = ports(filename_) 
  puts "\n\n====Ports====\n\n"
  open_ports.each do |key, values| 
    puts %Q(For host #{key} the following ports were discovered:\n    #{values.join("\n    ")}\n\n)
  end
else
  open_ports = []
end

if opts[:scope] then
  filename = scope(filename_) 
  puts "\n\n====BurpSuite Scope====\nScope file has been created and is here: #{filename}"
end

if opts[:web_scan] then
  total_scanned = web_scan(filename_) 
  puts "\n\n====Web Scans====\nScanning has been completed on #{total_scanned} targets. Output can be found here: #{filename_}"
end

puts "\n\nProgram completed. Files will be saved in the same directory as the nessus file :). \n\n".green




