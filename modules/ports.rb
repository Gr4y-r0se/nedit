require "Nokogiri"

def ports(file_)
	sorted_ips = []
	returnable = []
	file = File.open(file_) 

	doc = Nokogiri::XML(file)
	lst = doc.xpath('//ReportHost')

	for i in lst do sorted_ips.push(i['name']) end

	file.close

	sorted_ips.sort_by! {|ip| ip.split('.').map{ |octet| octet.to_i} }

	for ip in sorted_ips do
		ports = []
		
		path_ = '//ReportHost[@name="'+ip+'"]'
		host = doc.xpath(path_)

		for it in host.xpath('.//ReportItem') do
			port = it['port'] 
			unless ports.include? port or port == '0' then 
				ports.push(port)
			end
		end
		ports.sort_by! {|port| port.to_i}
		unless ports.length() == 0 then
			returnable.push(%Q(For host #{ip} the following ports were discovered:\n    #{ports.join("\n    ")}\n\n))
		end
	end
	return returnable
end