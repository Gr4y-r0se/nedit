require "Nokogiri"

def edit_mode(file_)
	
	done = false

	while done != true do
		vulns =[]
		file = File.open(file_) 

		doc = Nokogiri::XML(file)
		file.close
		full = doc.root
		lst = doc.xpath('//ReportItem')
		to_remove = []

		puts "\e[H\e[2J"
		puts "\nA list of vulnerabilites identifed (not including info's, use --info to remove those): \n\n"
		for i in lst do vulns.push(i['pluginName']) if i['severity'] !=  '0' end
		vulns = vulns.uniq
		vulns.each do |vuln|
			puts "    #{vulns.find_index(vuln) + 1}. #{vuln}"
		end

		print "\nEnter the numbers of ALL the vulnerabilites you want to remove (separated by spaces): "
		values = gets.gsub("\n",'')
		
		puts "\n\n"
		unless values == "exit" then
			values = values.split(" ").map(&:to_i)
		else
			puts "\n\n====Edit Mode====\nNessus file has been created and is here: #{file_}\n"
			done = true
			return
		end

		values.each do |value|
			puts "    #{vulns[value-1]}"
			to_remove.push(vulns[value-1])
		end
		print "\nAre you sure you want to remove all of these vulnerabilites? (y/n): "
		confirm = gets.gsub("\n",'')

		if confirm == "y" or confirm == 'yes' then 
			to_remove.each do |vuln|
				path_ = '//ReportItem[@pluginName="'+vuln+'"]'

				doc.search(path_).each do |node| 
					node.remove
				end
			end
			File.write(file_,doc)
		elsif confirm == "exit" then 
			puts "\n\n====Edit Mode====\nNessus file has been created and is here: #{file_}\n"
			
			done = true
		end
	end
end	
