['colorize','optimist'].each(&method(:require))

require_relative 'modules/csv'
require_relative 'modules/targets'
require_relative 'modules/hostnames'
require_relative 'modules/ports'
require_relative 'modules/edit'
require_relative 'modules/info'


#Parse commands, and display banner

opts = Optimist::options do
banner File.read('modules/banner.txt')
  opt :help, "Print this help message", :default => false
  opt :csv, "Nessus CSV Output - ITHC report annexe compatible", :default => false
  opt :targets, "Outputs the list of targets in the file", :default => false
  opt :hosts, "Outputs the list of targets and their hostnames (if availble)", :default => false
  opt :ports, "Outputs the list of targets and all the ports detected on that target", :default => false
  opt :edit, "Opens edit mode (type exit to close)", :default => false 
  opt :info, "Removes the informational findings from nessus files", :default => false 
  opt :file, "Specify the nessus file", :type => String
end

# Ensure mandatory parameters are present and Collisions don't happen 
Optimist::die :file, "- that file doesn't exist :).".red if !opts[:file] or File.file?(opts[:file]) == false

if opts[:info] then 
  info(opts[:file]) 
  puts "\n\n====Info Removal====\nNessus file has been updated and is here: #{opts[:file]}"
end

if opts[:edit] then edit_mode(opts[:file]) end

if opts[:csv] then 
  filename = csv(opts[:file]) 
  puts "\n\n====CSV Output====\nCSV file has been created and is here: #{filename}"
end

####Deals with the target printing

if opts[:targets] then 
  targets_ = targets(opts[:file]) 
  puts "\n\n====Targets====\n\n"
  targets_.each do |i| 
    puts i 
  end
else
  targets_ = []
end

####Deals with the hostname printing

if opts[:hosts] then 
  hosts = hostnames(opts[:file]) 
  puts "\n\n====Hostnames====\n\n"
  hosts.each do |i| 
    puts i 
  end
else
  hosts = []
end

####Deals with the port printing

if opts[:ports] then 
  open_ports = ports(opts[:file]) 
  puts "\n\n====Ports====\n\n"
  open_ports.each do |i| 
    puts i 
  end
else
  open_ports = []
end


puts "\n\nProgram completed. Files will be saved in the same directory as the nessus file :). \n\n".green













