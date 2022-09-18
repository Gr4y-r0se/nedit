require "Nokogiri"

def logs(file_)
	sorted_ips = []
	returnable = {}
	file = File.open(file_) 
	vulns = [] 
	doc = Nokogiri::XML(file)
	lst = doc.xpath('//ReportHost')
#Generate a list of all the vulns in the Nessus file
	doc.xpath('//ReportItem').each do |item|
		vuln = item['pluginName']
		unless vulns.include? vuln or item['severity'] == '0' then
			vulns.push(vuln)
		end
	end

	for i in lst do sorted_ips.push(i['name']) end #get list of ips

	csv = ["IP,Reference,Hostname,Port,What is it?,Notes,#{vulns.join(',')}"]

	file.close #close file

	sorted_ips.sort_by! {|ip| ip.split('.').map{ |octet| octet.to_i} } #sort ips logically

	for ip in sorted_ips do
		port_vulns = {}
		path_ = '//ReportHost[@name="'+ip+'"]'
		host = doc.xpath(path_)
		fqdnpath_ = host.xpath('.//tag[@name="host-fqdn"]')
		if fqdnpath_.length > 0 then
			fqdn = fqdnpath_.xpath('text()')
		else
			fqdn = ''
		end

		for it in host.xpath('.//ReportItem') do
			port = it['port'] 
			vuln = it['pluginName']

			if port_vulns.include? port and it['severity'] != '0'  then 
				port_vulns[port].push(vuln)
			elsif !port_vulns.include? port and it['severity'] != '0' then
				port_vulns[port] = [vuln]
			elsif port_vulns.include? port and it['severity'] == '0' then
				a = 1
			else
				port_vulns[port] = []
			end
			
		end

		#Generate an ordered hash from an unordered hash
		port_vulns = port_vulns.sort_by {|key,value| key.to_i}.to_h 
		csv_lines = []
		ip_ = ip
		fqdn_ = fqdn

		port_vulns.each do |key,value| 

			index_ = Array.new(vulns.length) { '' }
			csv_line = [ip_,sorted_ips.index(ip)+1,fqdn_,key,'','']
			ip_ = ''
			fqdn_ = ''

			for vuln in value do 
				index_[vulns.index(vuln)] = 'True' 
			end 
			csv_line += index_
			csv_lines.push(csv_line.join(','))
		end

		csv.push(csv_lines.join("\n"))
	end
	filename = "#{file_.rpartition('.')[0]}_logs.csv"
	File.write(filename,csv.join("\n"))
	return filename
end


#%Q(For host #{ip} the following ports were discovered:\n    #{ports.join("\n    ")}\n\n)