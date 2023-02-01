require "faraday"

require_relative "targets"
require_relative "ports"


def web_scan(file_)
	#Leverage Other Modules for Processing
	targets = targets(file_)
	open_ports = ports(file_)
	filepath = file_.rpartition('/')[0]
	target_fqdns = []
	targets.each do |i|
 		if not i.match(/^([01]?\d\d?|2[0-4]\d|25[0-5])(?:\.(?:[01]?\d\d?|2[0-4]\d|25[0-5])){3}(?:\/[0-2]\d|\/3[0-2])?$/) then
 			target_fqdns.append(i)
 		end
 	end
	target_fqdns = target_fqdns.sort
 	target_fqdns.each do |i|

 		system %Q(findomain -t #{i} -s "#{filepath}/#{i}")
 		if not File.directory?(%Q("#{filepath}/#{i}")) then 
 			system %Q(mkdir "#{filepath}/#{i}")
 		end
 		begin #catch http request errors
	 		req = Faraday.new "https://#{i}/robots.txt"
	 		resp = req.get
	 		if resp.status == 200 then 
	 			robots_file = resp.body 
	 		else 
	 			robots_file = "    Robots file was not found" 
	 		end
	 		headers = resp.headers
	 	rescue
	 		robots_file = "The request failed."
	 		headers = {"The request"=>"failed"}
	 	end
 		robots = %Q(robots.txt contained the following entrys:\n    #{robots_file}\n\n)
 		ports = %Q(The following open ports were discovered:\n    #{open_ports[i].join("\n    ")}\n\n)
 		headers = %Q(The following headers were discovered:\n#{(headers.map { |k,v| "     #{k}: #{v}" }).join("\n")}\n\n)
 		to_write = [robots,ports,headers]
 		File.write("#{filepath}/#{i}/details.txt",to_write.join("\n"))
 	end
 	return target_fqdns.length
end