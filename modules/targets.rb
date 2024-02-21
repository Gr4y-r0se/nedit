require "nokogiri"

def targets(file_)
	sorted = []
	file = File.open(file_) 

	doc = Nokogiri::XML(file)
	full = doc.root
	lst = doc.xpath('//ReportHost')

	for i in lst do sorted.push(i['name']) end

	file.close

	sorted = sorted.uniq

	sorted.sort_by! {|ip| ip.split('.').map{ |octet| octet.to_i} }

	return sorted
end