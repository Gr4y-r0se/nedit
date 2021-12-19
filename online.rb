require "Nokogiri"

require_relative "targets"

def online(file_)
	all_targets = []
	target_ips = []
	target_fqdns = []
	online = targets(file_)
	file = File.open(file_) 

	doc = Nokogiri::XML(file)

	lst = doc.xpath("//preference/name[text() = 'TARGET']")
	targets_list = lst.xpath('../value/text()').to_s.split(',').each
 	targets_list.each do |i|
 		if i.match(/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/) then
 			target_ips.append(i)
 		else
 			target_fqdns.append(i)
 		end
 	end
 	target_ips.sort_by! {|ip| ip.split('.').map{ |octet| octet.to_i} }
 	target_fqdns = target_fqdns.sort


	target_ips.concat(target_fqdns).each do |target|
		if online.include?(target) then
			all_targets.append("#{target} \t Online")
		else
			all_targets.append("#{target} \t Offline")

		end
	end
	file.close
	return all_targets
end