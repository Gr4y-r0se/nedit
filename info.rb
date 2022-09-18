require "Nokogiri"

def info(file_)

	file = File.open(file_) 

	doc = Nokogiri::XML(file)
	file.close
	for i in lst do vulns.push(i['pluginName']) if i['severity'] ==  '0' end

	to_remove.each do |vuln|
		path_ = '//ReportItem[@pluginName="'+vuln+'"]'
		doc.search(path_).each do |node| 
			node.remove
		end
	end
	File.write(file_,doc)
	return
end
