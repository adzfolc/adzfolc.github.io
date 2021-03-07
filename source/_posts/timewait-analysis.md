---
title: timewait-analysis
date: 2021-03-07 10:53:32
categories: Linux
tags: [Linux, Network, TCP, Cpp]
description: analyze the source of Linux kernel, and describe why&how TIME_WAIT is produced in TCP process, give device on how to avoid TIME_WAIT
---
在TCP中，主动关闭方进入TIME_WAIT，再回顾一下下面这张图。
<br/>
![tcp状态转换图](https://github.com/adzfolc/adzfolc.github.io/tree/master/pic/tcp.png)
![tcp报文头](https://github.com/adzfolc/adzfolc.github.io/tree/master/pic/tcp_packet.png)
<br/>

1. MSL
   1. 定义
    [rfc793](https://tools.ietf.org/html/rfc793#section-3.5)
   ```
   To be sure that a TCP does not create a segment that carries 
   a sequence number which may be duplicated by an old segment 
   remaining in the network, the TCP must keep quiet for a 
   maximum segment lifetime (MSL) before assigning any sequence 
   numbers upon starting up or recovering from a crash in which 
   memory of sequence numbers in use was lost.
   ```
   * TCP会位每次传出的TCP包携带序号，序号是可能会重复的，所以TCP需要保证每个TCP报文在网络中最多生存MSL时间。

2. TIME_WAIT
    1. 定义
    RFC793
    ```
    The only thing that can arrive in this state is a 
    retransmission of the remote FIN.  Acknowledge it, and 
    restart the 2 MSL timeout.
    ```
    * 只有收到对端的FIN包才会进入TIMWE_WAIT状态，在收到之后，会在2MSL时间之后重启。
    1. 分析
    * 主动断链方进入TIME_WAIT，网络中可能出现丢包的现象，主动方进入TIME_WAIT说明必定收到被动方的FIN和ACK，已经进入半关闭状态。半关闭状态，指主动方只能读取数据，不能写数据。主动关闭方为了确保对端可以收到我的ACK，所以在TIME_WAIT的时间内一直给对端不断发送ACK包，确保对端收到。
    * 防止`lost duplicate`和`incarnation connection`对TCP造成影响
      * `lost duplicate`
         TCP包在传输时，会被网络层包装成IP包，每个IP包都有TTL，即最大生存时间。IP包在经过路由器最多TTL次转发之后，就会消亡。如果路由器故障，IP包死循环，在路由器故障恢复之后又到达目的地。TCP由于超时重传机制，在发送数据包后，没收到ACK会超时重新这个数据包，两个相同的数据包先到达的被接收，后到达的被丢弃。
      * `incarnation connection`
         和上次TCP连接一模一样的连接
      * TCP是流式的，所有包到达的顺序是不一致的，依靠序列号由TCP协议栈做顺序的拼接。假设一个`incarnation connection`这时收到的seq=1000, 来了一个`lost duplicate`为seq=1000，len=1000, 则TCP认为这个lost duplicate合法，并存放入了receive buffer，导致传输出现错误。通过一个2MSL TIME_WAIT状态，确保所有的lost duplicate都会消失掉，避免对新连接造成错误。
    
3. TCP断链
   1. 短链接->Server响应后，主动断链，Server TIME_WAIT
   2. 长链接+空闲->Server空闲超时，发Fin，Server TIME_WAIT
   3. 长连接->Client结束，主动锻炼，Client TIME_WAIT

4. 问题重现
   1. Client与Server短链接通讯
   * Client主动断链，发送Fin包，Server端收到Fin包之后进入TIME_WAIT状态。高并发场景下，Server端大量TIME_WAIT,默认每个TIME_WAIT需要2MSL恢复(4秒)。
   * Linux默认端口范围在`/proc/sys/net/ipv4/ip_local_port_range`中定义，默认可用28233个端口。
   * 短链接，端口容易耗光，Server无法对外服务。

5. 解决分析
   1. 开启端口重用
   `setsockopt`函数设置`SO_REUSEADDR`参数
   * SO_REUSEADDR允许启动一个监听服务器并捆绑其众所周知端口，即使以前建立的将此端口用做他们的本地端口的连接仍存在。这通常是重启监听服务器时出现，若不设置此选项，则bind时将出错。
   * SO_REUSEADDR允许在同一端口上启动同一服务器的多个实例，只要每个实例捆绑一个不同的本地IP地址即可。对于TCP，我们根本不可能启动捆绑相同IP地址和相同端口号的多个服务器。
   * SO_REUSEADDR允许单个进程捆绑同一端口到多个套接口上，只要每个捆绑指定不同的本地IP地址即可。这一般不用于TCP服务器。
   * SO_REUSEADDR允许完全重复的捆绑：当一个IP地址和端口绑定到某个套接口上时，还允许此IP地址和端口捆绑到另一个套接口上。一般来说，这个特性仅在支持多播的系统上才有，而且只对UDP套接口而言（TCP不支持多播）
   * 总结
     * 在C/Cpp底层可以自己封装的服务器中，可以通过`SO_REUSEADDR`实现端口复用；但是，在底层封装好的中间件上，不能这么设置，或者进行自己修改，二次开发部署。
   2. 设置Linux内核`tw_recycle`参数

6. 测试过程
   1. 修改前端HTTP报文头的`Closed`为`Keepalive`，但是Tomcat发送出去后，这个链接默认是短链接，修改报文头不会生效。
   2. 设置`reuse`参数，`reuse`参数在全部都是TIME_WAIT时，会复用TIME_WAIT状态的端口进行通信。模拟Client和Server测试，Client受到限制，在`/etc/security/limits.conf`文件中，限制了Linux的最大进程数，普通用户默认最大进程数是1024，受到这些限制，所以`reuse`参数的效果很难真正的测试出来。
   3. 设置`recycle`参数，各种场景下测试，TIME_WAIT的数量都在20以下。

7. 注意事项
   1. 开启`recycle`快速回收TIME_WAIT端口，要求不能开启NAT，不然会大量丢包

8. 代码分析
   `linux-2.6.10\net\ipv4\tcp_minisocks.c`

   ```c
   enum tcp_tw_status
   tcp_timewait_state_process(struct tcp_tw_bucket *tw, struct sk_buff *skb,
			   struct tcphdr *th, unsigned len)
   {
   /* I am shamed, but failed to make it more elegant.
		 * Yes, it is direct reference to IP, which is impossible
		 * to generalize to IPv6. Taking into account that IPv6
		 * do not undertsnad recycling in any case, it not
		 * a big problem in practice. --ANK */
   //本地Socket是ipv4
	if (tw->tw_family == AF_INET &&
   //sysctl -p 生效TCP参数修改
   //本机系统开启tcp_tw_recycle选项
   //tw->tw_ts_recent_stamp	= tp->ts_recent_stamp;
   //tw本端 tp对端 内核缓存对端的上次timestamp序号
	sysctl_tcp_tw_recycle && tw->tw_ts_recent_stamp &&
   //内核缓存这次的stamp(tw)用于下次比较
	tcp_v4_tw_remember_stamp(tw))
	tcp_tw_schedule(tw, tw->tw_timeout);
	else
		tcp_tw_schedule(tw, TCP_TIMEWAIT_LEN);
   return TCP_TW_ACK;
   }
   ```

   `linux-2.6.10\include\net\tcp.h`

   ```c
   #define TCP_PAWS_MSL	60		/* Per-host timestamps are invalidated
					 * after this time. It should be equal
					 * (or greater than) TCP_TIMEWAIT_LEN
					 * to provide reliability equal to one
					 * provided by timewait state.
					 */
   #define TCP_PAWS_WINDOW	1		/* Replay window for per-host
					 * timestamps. It must be less than
					 * minimal timewait lifetime.
					 */
   ```

   `linux-2.6.10\kernel\timer.c`

   ```c
   /* 
    * The current time 
    * wall_to_monotonic is what we need to add to xtime (or xtime corrected 
    * for sub jiffie times) to get to monotonic time.  Monotonic is pegged at zero
    * at zero at system boot time, so wall_to_monotonic will be negative,
    * however, we will ALWAYS keep the tv_nsec part positive so we can use
    * the usual normalization.
    */
    // wall time字面意思是挂钟时间，实际上就是指的是现实的时间，这是由变量xtime来记录的。系统每次启动时将CMOS上的RTC时间读入xtime，这个值是"自1970-01-01起经历的秒数、本秒中经历的纳秒数"，每来一个timer interrupt，也需要去更新xtime。
   struct timespec xtime __attribute__ ((aligned (16)));
   // monotonic time字面意思是单调时间，实际上它指的是系统启动以后流逝的时间，这是由变量jiffies来记录的。系统每次启动时jiffies初始化为0，每来一个timer interrupt，jiffies加1，也就是说它代表系统启动后流逝的tick数。
   struct timespec wall_to_monotonic __attribute__ ((aligned (16)));
   ```

   `linux-2.6.10\net\ipv4\tcp_ipv4.c`

   ```c
   int tcp_v4_conn_request(struct sock *sk, struct sk_buff *skb)
   {
      ...
      /* VJ's idea. We save last timestamp seen
	   * from the destination in peer table, when entering
	   * state TIME-WAIT, and check against it before
	   * accepting new connection request.
	   * If "isn" is not zero, this request hit alive
	   * timewait bucket, so that all the necessary checks
	   * are made in the function processing timewait state.
	   */
      //char	saw_tstamp;	/* Saw TIMESTAMP on last packet		*/
	   if (tp.saw_tstamp &&
      // 是否见到过tcp_timestamp选项
		sysctl_tcp_tw_recycle &&
		(dst = tcp_v4_route_req(sk, req)) != NULL &&
		(peer = rt_get_peer((struct rtable *)dst)) != NULL &&
		peer->v4daddr == saddr) {
		if (xtime.tv_sec < peer->tcp_ts_stamp + TCP_PAWS_MSL &&TCP_PAWS_WINDOW=1
		(s32)(peer->tcp_ts - req->ts_recent) > TCP_PAWS_WINDOW) {
			NET_INC_STATS_BH(LINUX_MIB_PAWSPASSIVEREJECTED);
			dst_release(dst);
			goto drop_and_free;
		   }
	   }
      ...
   }
   ```

   `linux-3.10\net\ipv4\tcp_ipv4.c`

   ```c
   int tcp_v4_conn_request(struct sock *sk, struct sk_buff *skb)
   {
      ...
   /* VJ's idea. We save last timestamp seen
		 * from the destination in peer table, when entering
		 * state TIME-WAIT, and check against it before
		 * accepting new connection request.
		 *
		 * If "isn" is not zero, this request hit alive
		 * timewait bucket, so that all the necessary checks
		 * are made in the function processing timewait state.
		 */
      //char	saw_tstamp;	/* Saw TIMESTAMP on last packet		*/
      // 是否见到过tcp_timestamp选项
		if (tmp_opt.saw_tstamp &&
         // 接着判断是否开启recycle
		    tcp_death_row.sysctl_tw_recycle &&
		   // 最终判断saddr是否有相关记录在route表中
          (dst = inet_csk_route_req(sk, &fl4, req)) != NULL &&
		    fl4.daddr == saddr) {
         // 如果这个建连请求不能被proven，则会被丢弃
			if (!tcp_peer_is_proven(req, dst, true)) {
				NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_PAWSPASSIVEREJECTED);
				goto drop_and_release;
			}
		}
      ...
   }
   ```

   `linux-3.10\net\ipv4\tcp_metrics.c`

   ```c
   // 负责判断接收到的request请求的timestamp是否符合要求
   bool tcp_peer_is_proven(struct request_sock *req, struct dst_entry *dst, bool paws_check)
   {
	   struct tcp_metrics_block *tm;
	   bool ret;

	   if (!dst)
	   	return false;

	   rcu_read_lock();
	   tm = __tcp_get_metrics_req(req, dst);
	   if (paws_check) {
	   	if (tm &&
            // 判断保存tcpm_ts_stamp值是否有效，TCP_PAWS_MSL=60
	   	    (u32)get_seconds() - tm->tcpm_ts_stamp < TCP_PAWS_MSL &&
            // 如果记录值大于当前收到的req中的timestamp值，则丢弃。TCP_PAWS_WINDOW=1
	   	    (s32)(tm->tcpm_ts - req->ts_recent) > TCP_PAWS_WINDOW)
	   		ret = false;
	   	else
	   		ret = true;
	   } else {
	   	if (tm && tcp_metric_get(tm, TCP_METRIC_RTT) && tm->tcpm_ts_stamp)
			ret = true;
	   	else
		   	ret = false;
	   }
	   rcu_read_unlock();

	   return ret;
   }
   ```

   `linux-3.10\net\ipv4\tcp_minisocks.c`

   ```c
   /*
   * Move a socket to time-wait or dead fin-wait-2 state.
   */
   void tcp_time_wait(struct sock *sk, int state, int timeo)
   {
      struct inet_timewait_sock *tw = NULL;
      const struct inet_connection_sock *icsk = inet_csk(sk);
      const struct tcp_sock *tp = tcp_sk(sk);
      bool recycle_ok = false;

      //long	ts_recent_stamp;/* Time we stored ts_recent (for aging) */
      if (tcp_death_row.sysctl_tw_recycle && tp->rx_opt.ts_recent_stamp)
         //内核缓存这次的时间戳
         recycle_ok = tcp_remember_stamp(sk);

      if (tcp_death_row.tw_count < tcp_death_row.sysctl_max_tw_buckets)
         tw = inet_twsk_alloc(sk, state);

      ...

         /* Get the TIME_WAIT timeout firing. */
         if (timeo < rto)
         //const int rto = (icsk->icsk_rto << 2) - (icsk->icsk_rto >> 1);
         //3.5倍rto
            timeo = rto;

         //开启recycle
         if (recycle_ok) {
            //TIME_WAIT缩短成3.5倍rto
            tw->tw_timeout = rto;
         } else {
         //#define TCP_TIMEWAIT_LEN (60*HZ) /* how long to wait to destroy TIME-WAIT state, about 60 seconds	*/
            tw->tw_timeout = TCP_TIMEWAIT_LEN;
            if (state == TCP_TIME_WAIT)
               timeo = TCP_TIMEWAIT_LEN;
         }

         ...
      }

      tcp_update_metrics(sk);
      tcp_done(sk);
   }
   ```