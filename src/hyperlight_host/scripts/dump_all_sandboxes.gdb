define dump_all_sandboxes
  set pagination off
  
  # Get the total number of threads
  info threads
  
  # Loop through all threads (adjust max if you have more than 200 threads)
  set $thread_num = 2
  while $thread_num <= 200
    # Try to switch to this thread
    thread $thread_num
    
    # Check if thread switch succeeded (GDB sets $_thread to current thread)
    if $_thread == $thread_num
      echo \n=== Thread 
      p $thread_num
      echo ===\n
      
      # Go to frame 15
      frame 15
      
      
      set $sb = &sandbox
      call sandbox.generate_crashdump()
      
      set $thread_num = $thread_num + 1
    else
      # No more threads, exit loop
      set $thread_num = 201
    end
  end
  
  echo \nDone dumping all sandboxes\n
  set pagination on
end

document dump_all_sandboxes
Dump crashdumps for sandboxes on all threads (except thread 1).
Assumes sandbox is in frame 15 on each thread.
Usage: dump_all_sandboxes
end