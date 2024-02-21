require "nokogiri"
require 'rubygems'
require 'ipaddr'

require_relative "targets"

def online(file_)
	all_targets = []
	target_ips = []
	target_fqdns = []
	online = targets(file_)
	file = File.open(file_) 

	doc = Nokogiri::XML(file)
	regex = "/^([01]?\d\d?|2[0-4]\d|25[0-5])(?:\.(?:[01]?\d\d?|2[0-4]\d|25[0-5])){3}(?:/[0-2]\d|/3[0-2])?$/"
	lst = doc.xpath("//preference/name[text() = 'TARGET']")
	targets_list = lst.xpath('../value/text()').to_s.split(',')
 	targets_list.each do |i|
 		if i.match(/^([01]?\d\d?|2[0-4]\d|25[0-5])(?:\.(?:[01]?\d\d?|2[0-4]\d|25[0-5])){3}(?:\/[0-2]\d|\/3[0-2])?$/) then
 			if i.include? '/' then 
 				values = IPAddr.new(i).to_range()
 				values.each do |ip|
 					target_ips.append(ip.to_s)
 				end
 			else
 				target_ips.append(i)
 			end
 		else
 			target_fqdns.append(i)
 		end
 	end
 	target_ips.uniq!
 	target_ips.sort_by! {|ip| ip.split('.').map{ |octet| octet.to_i} }
 	target_fqdns = target_fqdns.sort
 	
	target_ips.concat(target_fqdns).each do |target|
		if online.include?(target) then
			all_targets.push("#{target} \t Online")
		else
			all_targets.push("#{target} \t Offline")

		end
	end
	file.close
	return all_targets
end