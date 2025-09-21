require "nokogiri"

def compliance_checks(xml,hostdetails)
	checks = {}
	for item in hostdetails do
		hostname,compliance_name = item,hostdetails[item]
		path_ = '//ReportHost[@name="'+hostname+'"]/ReportItem[@pluginName="'+compliance_name+'"]'
		compliance_lst = xml.xpath(path_)

		# Order is: Result, Check_Name, Benchmark_Name, Check_Info, Check_Result, See_Also

		for i in compliance_lst do 
			checks[i.xpath('.//cm:compliance-check-name/text()', {'cm' => 'http://www.nessus.org/cm'}).to_s] = [
				i.xpath('.//cm:compliance-result/text()', {'cm' => 'http://www.nessus.org/cm'}).to_s.strip[...6000].gsub('"',"'").gsub('&quot;',"'"),
				i.xpath('.//cm:compliance-benchmark-name/text()', {'cm' => 'http://www.nessus.org/cm'}).to_s.strip[...6000].gsub('"',"'").gsub('&quot;',"'"),
				i.xpath('.//cm:compliance-info/text()', {'cm' => 'http://www.nessus.org/cm'}).to_s.strip[...6000].gsub('"',"'").gsub('&quot;',"'"),
				i.xpath('.//cm:compliance-actual-value/text()', {'cm' => 'http://www.nessus.org/cm'}).to_s.strip[...6000].gsub('"',"'").gsub('&quot;',"'"),
				i.xpath('.//cm:compliance-see-also/text()', {'cm' => 'http://www.nessus.org/cm'}).to_s.strip[...6000].gsub('"',"'").gsub('&quot;',"'")
			]
		end
		

		writeable = ['"Compliance Check Title","Result","Benchmark Name","Description","Details","See Also"']

		checks.each do |title, values|
			writeable.push(%Q("#{title}","#{values[0]}","#{values[1]}","#{values[2]}","#{values[3]}","#{values[4]}"))
		end

		filename = host + "_compliance-results.csv"
		File.write(filename,csv_structure.join("\n"))
	end

	return 
end


def csv(file_)
	vulns = {}
	file = File.open(file_) 
	
	#For detecting Compliance Checks
	compliance = false
	compliance_checks_record = {}
	checks_filename = ''

	doc = Nokogiri::XML(file)
	full = doc.root
	lst = doc.xpath('//ReportItem')

	#My gin addled brain needed this so I could make sense of the nested hash value:
	# [0 - CVE],[1 - CVSS 3 score],[2 - Risk/Severity],[3 - Ip address],[4 - Protocol],[5 - Socket],[6- Description],[7 - Remediation],[8 - External References],[9 - plugin output],[10 - hostname],[11 - rdns]

	#This declares a default value for all the vulnerabilites, which we will later populate
	for i in lst do 
		if i['pluginName'].include? 'Compliance Checks' then
			compliance = true
			compliance_checks_record[i.xpath('..')[0]['name']] = i['pluginName']
		elsif i['severity'] !=  '0' then
			vulns[i['pluginName']] ||= [[],[],[],[],[],[],[],[],[],[],[],[]]  
		end  
	end
	
	if compliance == true then
		puts "\n	Detected #{check_name} - Generating #{compliance_checks_record.length} Additional Spreadsheet(s)."
		csv_structure = compliance_checks(doc,compliance_checks_record)
	end

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

			
			#This is a janky solution - plz fi
			original_hosthames = values[10].length
			for it in parent_element.xpath('.//tag[@name="hostname"]') do
				hostname = it.xpath('text()')
				values[10].push(hostname)
			end
			if original_hosthames == values[10].length then
				values[10].push(ip)
			end
			original_rdns = values[11].length
			for it in parent_element.xpath('.//tag[@name="host-rdns"]') do
				rdns = it.xpath('text()')
				values[11].push(rdns)
			end
			if original_rdns == values[11].length then
				values[11].push(ip)
			end
		end

		for port in vuln_path do
			ip = port.xpath('..')[0]['name'].to_s.strip
			values[5].push(ip+':'+port['port'])
		end

		for protocol in vuln_path do
			values[4].push(protocol['protocol'])
		end

		for description in vuln_path.xpath('.//description') do
			values[6] = description.xpath('text()').to_s.strip[...6000]
		end

		for remediation in vuln_path.xpath('.//solution') do
			values[7] = remediation.xpath('text()').to_s.strip[...6000]
		end

		for external_references in vuln_path.xpath('.//see_also') do
			values[8].push(external_references.xpath('text()').to_s.strip[...6000])
		end

		for plugin_output in vuln_path.xpath('.//plugin_output') do
			values[9].push(plugin_output.xpath('text()').to_s.strip[...6000].gsub('"',"'").gsub('&quot;',"'")) # This line deals with the HSTS finding rather well.
		end
	end



	file.close

	writeable = ['"Vulnerability","CVE","CVSS 3 score","Risk/Severity","IP address","Hostname","rDNS","Protocol","Socket","Description","Remediation","External References","Plugin Output"']

	filename = "#{file_.rpartition('.')[0]}.csv"

	vulns.each do |vuln , values|
		writeable.push(%Q("#{vuln}","#{values[0].join("\n")}","#{values[1]}","#{values[2]}","#{values[3].join("\n")}","#{values[10].join("\n")}","#{values[11].join("\n")}","#{values[4].join("\n")}","#{values[5].join("\n")}","#{values[6]}","#{values[7]}","#{values[8].uniq.join("\n")}","#{values[9].uniq.join("\n")}"))
	end

	File.write(filename,writeable.join("\n"))
	if checks_filename != '' then
		filename = filename + " and #{checks_filename}"
	end
	return filename
end

