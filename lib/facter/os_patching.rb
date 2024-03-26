# Ensure that this fact does not try to be loaded
# on old (pre v.2) versions of facter as it uses
# aggregate facts
if Facter.value(:facterversion).split('.')[0].to_i < 2
  Facter.add('os_patching') do
    setcode do
      'not valid on legacy facter versions'
    end
  end
else
  Facter.add('os_patching', :type => :aggregate) do
    pkgs = `yum -q check-update 2>/dev/null | egrep -v "^[Ss]ecurity:" | grep -oP '^.*?(?= )' | sed 's/Obsoleting.*//'`.split("\n")
    sec_pkgs = `yum -q --security check-update 2>/dev/null | egrep -v "^Security:" | grep -oP '^.*?(?= )' | sed 's/Obsoleting.*//'`.split("\n")
    held_pkgs = `[ -r /etc/yum/pluginconf.d/versionlock.list ] && awk -F':' '/:/ {print $2}' /etc/yum/pluginconf.d/versionlock.list | sed 's/-[0-9].*//'`.split("\n")

    vardir = `puppet config print vardir`.strip
    catalog = vardir + "/client_data/catalog/" + `puppet config print certname --section agent`.strip + ".json"

    confine { ['FreeBSD', 'Linux', 'windows'].include?(Facter.value(:kernel)) }
    require 'time'
    now = Time.now.iso8601
    warnings = {}
    blocked = false
    blocked_reasons = []

    case Facter.value(:kernel)
    when 'FreeBSD', 'Linux'
      os_patching_dir = '/var/cache/os_patching'
    when 'windows'
      os_patching_dir = 'C:\ProgramData\os_patching'
    end

    chunk(:agent_type) do
      data = {}
      if Facter.value(:aio_agent_build) =~ /[0-9]/
        data['agent_type'] = 'PE'
      else
        data['agent_type'] = 'OSP'
      end
      data
    end

    chunk(:updates) do
      data = {}
      data['package_updates'] = pkgs
      data['package_update_count'] = pkgs.count
      data
    end

    chunk(:kb_updates) do
      data = {}
      kblist = []
      kbfile = os_patching_dir + '/missing_update_kbs'
      if File.file?(kbfile) && !File.zero?(kbfile)
        kbs = File.open(kbfile, 'r').read
        kbs.each_line do |line|
          kblist.push line.chomp
        end
      end
      data['missing_update_kbs'] = kblist
      data
    end

    chunk(:secupdates) do
      data = {}
      data['security_package_updates'] = sec_pkgs
      data['security_package_update_count'] = sec_pkgs.count
      data
    end

    chunk(:blackouts) do
      data = {}
      arraydata = {}
      blackoutfile = os_patching_dir + '/blackout_windows'
      if File.file?(blackoutfile)
        blackouts = File.open(blackoutfile, 'r').read
        blackouts.each_line do |line|
          next if line.empty?
          next if line =~ /^#|^$/
          matchdata = line.match(/^([\w ]*),(\d{,4}-\d{1,2}-\d{1,2}T\d{,2}:\d{,2}:\d{,2}\+\d{,2}:\d{,2}),(\d{,4}-\d{1,2}-\d{1,2}T\d{,2}:\d{,2}:\d{,2}[-\+]\d{,2}:\d{,2})$/)
          if matchdata
            arraydata[matchdata[1]] = {} unless arraydata[matchdata[1]]
            if matchdata[2] > matchdata[3]
              arraydata[matchdata[1]]['start'] = 'Start date after end date'
              arraydata[matchdata[1]]['end'] = 'Start date after end date'
              warnings['blackouts'] = matchdata[0] + ' : Start data after end date'
            else
              arraydata[matchdata[1]]['start'] = matchdata[2]
              arraydata[matchdata[1]]['end'] = matchdata[3]
            end

            if (matchdata[2]..matchdata[3]).cover?(now)
              blocked = true
              blocked_reasons.push matchdata[1]
            end
          else
            warnings['blackouts'] = "Invalid blackout entry : #{line}"
            blocked = true
            blocked_reasons.push "Invalid blackout entry : #{line}"
          end
        end
      end
      data['blackouts'] = arraydata
      data
    end

    # Are there any pinned/version locked packages?
    chunk(:pinned) do
      require 'json'

      data = {}
      pinned_list = []

      File.open(catalog, 'r') do |file|
        json_hash = JSON.load file
        json_hash['resources'].select { |r| r['type'] == 'Package' and r['parameters']['ensure'] and r['parameters']['ensure'].match /\d.+/ }.each do | m |
          pinned_list.push(m['title'])
        end
        data['pinned_packages'] = pinned_list
      end

      #pinned_list.each do | pkg |
      #  p "Checking pinned_list"
      #  if held_pkgs.include?(pkg)
      #    p "Adding warning"
      #    warnings['version_specified_but_not_locked_packages'].push pkg
      #    p "Warning added"
      #end
      data
    end

    # History info
    chunk(:history) do
      data = {}
      patchhistoryfile = os_patching_dir + '/run_history'
      data['last_run'] = {}
      if File.file?(patchhistoryfile)
        historyfile = File.open(patchhistoryfile, 'r').to_a
        line = historyfile.last.chomp
        matchdata = line.split('|')
        if matchdata[1]
          data['last_run']['date'] = matchdata[0]
          data['last_run']['message'] = matchdata[1]
          data['last_run']['return_code'] = matchdata[2]
          data['last_run']['post_reboot'] = matchdata[3]
          data['last_run']['security_only'] = matchdata[4]
          data['last_run']['job_id'] = matchdata[5]
        end
      end
      data
    end

    # Patch window
    chunk(:patch_window) do
      data = {}
      patchwindowfile = os_patching_dir + '/patch_window'
      if File.file?(patchwindowfile)
        patchwindow = File.open(patchwindowfile, 'r').to_a
        line = patchwindow.last
        matchdata = line.match(/^(.*)$/)
        if matchdata[0]
          data['patch_window'] = matchdata[0]
        end
      else
        data['patch_window'] = ''
      end
      data
    end

    # Reboot override
    chunk(:reboot_override) do
      rebootfile = os_patching_dir + '/reboot_override'
      data = {}
      if File.file?(rebootfile)
        rebootoverride = File.open(rebootfile, 'r').to_a
        data['reboot_override'] = case rebootoverride.last
                                  when /^always$/
                                    'always'
                                  when /^[Tt]rue$/
                                    'always'
                                  when /^[Ff]alse$/
                                    'never'
                                  when /^never$/
                                    'never'
                                  when /^patched$/
                                    'patched'
                                  when /^smart$/
                                    'smart'
                                  else
                                    'default'
                                  end
      else
        data['reboot_override'] = 'default'
      end
      data
    end

    # Reboot or restarts required?
    chunk(:reboot_required) do
      p "Getting reboot required"
      data = {}
      data['reboots'] = {}

      reboot = `/usr/bin/needs-restarting -r 2>/dev/null 1>/dev/null`.split("\n")
      unless reboot.empty?
        data['reboots']['reboot_required'] = true
      else
        data['reboots']['reboot_required'] = false
      end

      p "Checking apps that need restart"
      apps_restart = `/usr/bin/needs-restarting 2>/dev/null | grep -v 'Updating Subscription Management repositories' | sed 's/[[:space:]]*$//'`.split("\n")
      data['reboots']['apps_needing_restart'] = apps_restart

      unless data['reboots']['apps_needing_restart'].empty?
        data['reboots']['app_restart_required'] = true
      else
        data['reboots']['app_restart_required'] = false
      end
      data
    end

    # Should we patch if there are warnings?
    chunk(:pre_patching_command) do
      data = {}
      pre_patching_command = os_patching_dir + '/pre_patching_command'
      if File.file?(pre_patching_command) && !File.empty?(pre_patching_command)
        command = File.open(pre_patching_command, 'r').to_a
        line = command.last
        matchdata = line.match(/^(.*)$/)
        if matchdata[0]
          if File.file?(matchdata[0])
            if File.executable?(matchdata[0])
              data['pre_patching_command'] = matchdata[0]
            else
              warnings['blackouts'] = "Pre_patching_command not executable : #{matchdata[0]}"
              blocked = true
              blocked_reasons.push "Pre_patching_command not executable : #{matchdata[0]}"
            end
          else
            warnings['pre_patching_command'] = "Invalid pre_patching_command entry : #{matchdata[0]}.  File must exist and be a single command with no arguments"
            blocked = true
            blocked_reasons.push "Invalid pre_patching_command entry : #{matchdata[0]}.  File must exist and be a single command with no arguments"
          end
        end
      end
      data
    end

    # Should we patch if there are warnings?
    chunk(:block_patching_on_warnings) do
      data = {}
      abort_on_warningsfile = os_patching_dir + '/block_patching_on_warnings'
      if File.file?(abort_on_warningsfile)
        data['block_patching_on_warnings'] = 'true'
        unless warnings.empty?
          blocked = true
          blocked_reasons.push warnings
        end
      else
        data['block_patching_on_warnings'] = 'false'
        data['warnings'] = warnings
      end
      data['blocked'] = blocked
      data['blocked_reasons'] = blocked_reasons
      data
    end
  end
end
