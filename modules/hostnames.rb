require "nokogiri"

def hostnames(file_)
	sorted_ips = []
	file = File.open(file_) 

	doc = Nokogiri::XML(file)
	lst = doc.xpath('//ReportHost')

	for i in lst do sorted_ips.push(i['name']) end

	file.close

	sorted_ips.sort_by! {|ip| ip.split('.').map{ |octet| octet.to_i} }
	hostnames_ = []
	for ip in sorted_ips do
		
		path_ = '//ReportHost[@name="'+ip+'"]'
		host = doc.xpath(path_)

		for it in host.xpath('.//tag[@name="hostname"]') do
			hostname = it.xpath('text()').to_s
		end

		for it in host.xpath('.//tag[@name="host-rdns"]') do 
			rdns = it.xpath('text()').to_s
		end

		if !hostname then
			hostnames_.push("#{ip} - #{rdns}.\n")
		else
			hostnames_.push("#{ip} - #{hostname} - #{rdns}\n")
		end
	end

	return hostnames_
end 