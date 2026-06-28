def _parse_logs(self, start_time: str, end_time: str):
    """Actual parsing logic - runs in background"""
    try:
        total_lines = 0
        processed_lines = 0
        
        # First, count total lines for progress
        with open(self.log_file, 'r') as f:
            total_lines = sum(1 for _ in f)
        
        with open(self.log_file, 'r') as f:
            for line in f:
                processed_lines += 1
                self.progress = int((processed_lines / total_lines) * 100) if total_lines > 0 else 0
                
                # Extract timestamp
                ts = get_log_timestamp(line)
                if not ts:
                    continue
                
                # DEBUG: Print first few timestamps to see what we're comparing
                # Uncomment to debug:
                # if processed_lines <= 5:
                #     print(f"DEBUG: ts='{ts}', start='{start_time}', end='{end_time}'")
                
                # Check time range - REMOVE THE BRACKETS FOR COMPARISON
                # The timestamp from log is like "28/Jun/2026:00:01:34 +0530"
                # The start_time is like "[28/Jun/2026:00:00:00"
                # So we need to compare properly
                
                # Clean both for comparison - remove brackets and timezone
                ts_clean = ts.split(' +')[0]  # Remove timezone part
                start_clean = start_time.replace('[', '').replace(']', '')
                end_clean = end_time.replace('[', '').replace(']', '')
                
                # Now compare as strings (lexicographically works for this format)
                if ts_clean < start_clean or ts_clean > end_clean:
                    continue
                
                # Extract fields
                parts = line.split()
                if len(parts) < 10:
                    continue
                
                status = parts[8] if len(parts) > 8 else "0"
                ip = parts[0]
                
                # Count 403 but skip
                if status == "403":
                    self.total_403 += 1
                    self.status_count[status] += 1
                    continue
                
                self.total_requests += 1
                self.status_count[status] += 1
                
                if status in ["200", "304"]:
                    self.total_ok += 1
                    self.ip_count[ip] += 1
                    
                    # Extract URL
                    url = parts[6] if len(parts) > 6 else "/"
                    self.url_count[url] += 1
                    
                    # Extract query string
                    if '?' in url:
                        query = url.split('?', 1)[1]
                        self.query_count[query] += 1
                    else:
                        self.query_count["(no query)"] += 1
                    
                    # Extract hour for hourly stats
                    if match := re.search(r'(\d{2}:\d{2})', ts):
                        hour = match.group(1)
                        if hour not in self.hourly_ok:
                            self.hourly_ok[hour] = 0
                            self.hourly_range[f"{hour}_start"] = ts
                        self.hourly_ok[hour] += 1
                        self.hourly_range[f"{hour}_end"] = ts
                else:
                    self.total_errors += 1
                
                # Extract User-Agent
                ua_match = re.search(r'"[^"]*"$', line)
                if ua_match:
                    ua = ua_match.group(0).strip('"')
                    if ua and ua != "-":
                        self.ua_count[ua] += 1
        
        self.is_done = True
        self.is_processing = False
        
    except Exception as e:
        self.is_processing = False
        self.is_done = True
        print(f"{Colors.RED}Error parsing logs: {e}{Colors.NC}")
