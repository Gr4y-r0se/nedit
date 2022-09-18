 require_relative 'ports'

def scope(file)
	scope_data = ports(file)

	json_frags = []
	filename = "#{file.rpartition('.')[0]}.json"

	
	scope_data.each do |url,ports|
		url = url.sub(/^https?\:\/\//,'')
		url = url.gsub(/\./,'\\\\\.')
		url = "^#{url}$"
		ports.each do |port|
			json_frag = %Q({
		        "enabled": true,
		        "file": "^/.*",
		        "host": "#{url}",
		        "port": "^#{port}$",
		        "protocol": "http"},
		        {
		        "enabled": true,
		        "file": "^/.*",
		        "host": "#{url}",
		        "port": "^#{port}$",
		        "protocol": "https"}
		        )
		   	json_frags.append(json_frag)
	   	end
	end


	scope_json = %Q({
	    "target": {
	        "scope": {
	            "advanced_mode": true,
	            "include": [
	            	#{json_frags.join(',')}
	            ]
	        }
	    }
	})

	File.write(filename,scope_json)
	return filename
end