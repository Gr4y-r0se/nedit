require "Nokogiri"


def csv(file_)
	vulns = {}
	file = File.open(file_) 

	doc = Nokogiri::XML(file)
	full = doc.root
	lst = doc.xpath('//ReportItem')

	#My gin addled brain needed this so I could make sense of the nested hash value:
	# [0 - CVE],[1 - CVSS 3 score],[2 - Risk/Severity],[3 - Ip address],[4 - Protocol],[5 - Port],[6- Description],[7 - Remediation],[8 - External References],[9 - plugin output],[10 - hostname]

	for i in lst do vulns[i['pluginName']] ||= [[],[],[],[],[],[],[],[],[],[],[]] if i['severity'] !=  '0' end  #This declares a default value for all the vulnerabilites, which we will later populate
	 

	vulns.each do |vuln , values|
		path_ = '//ReportItem[@pluginName="'+vuln+'"]'
		vuln_path = doc.xpath(path_)

		for cve_code in vuln_path.xpath('.//cve') do
			values[0].push(cve_code.xpath('text()').to_s)
		end
		for cvss_score in vuln_path.xpath('.//cvss3_base_score') do
			values[1] = cvss_score.xpath('text()').to_s
		end
		for risk_factor in vuln_path.xpath('.//risk_factor') do
			values[2] = risk_factor.xpath('text()').to_s
		end

		for parent_element in vuln_path.xpath('..') do
			ip = parent_element['name']
			values[3].push(ip)
			for it in parent_element.xpath('.//tag[@name="hostname"]') do
				hostname = it.xpath('text()')
				if hostname != '' then 
					values[10].push(hostname)
				else 
					values[10].push("N/A")
				end
			end
		end

		for protocol in vuln_path do
			values[4].push(protocol['protocol'])
		end

		for port in vuln_path do
			values[5].push(port['port'])
		end

		for description in vuln_path.xpath('.//description') do
			values[6] = description.xpath('text()').to_s
		end
		for remediation in vuln_path.xpath('.//solution') do
			values[7] = remediation.xpath('text()').to_s
		end
		for external_references in vuln_path.xpath('.//see_also') do
			values[8].push(external_references.xpath('text()').to_s)
		end
		for plugin_output in vuln_path.xpath('.//plugin_output') do
			values[9].push(plugin_output.xpath('text()').to_s)
		end
	end



	file.close

	writeable = ['"Vulnerability","CVE","CVSS 3 score","Risk/Severity","IP address","Hostname","Protocol","Ports","Description","Remediation","External References","Plugin Output"']

	filename = "#{file_.rpartition('.')[0]}.csv"

	vulns.each do |vuln , values|
		writeable.push(%Q("#{vuln}","#{values[0].join("\n")}","#{values[1]}","#{values[2]}","#{values[3].join("\n")}","#{values[10].join("\n")}","#{values[4].join("\n")}","#{values[5].join("\n")}","#{values[6]}","#{values[7]}","#{values[8].uniq.join("\n")}","#{values[9].uniq.join("\n")}"))
	end

	File.write(filename,writeable.join("\n"))

	return filename
end



