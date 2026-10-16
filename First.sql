--SELECT * FROM network_flows Where import_batch_id = 9 AND original_label != 'BENIGN' AND original_label != 'Web Attack - Brute Force' AND original_label != 'Web Attack - XSS' order by id limit 100
--SELECT SUM (IMPORT_BATCH_ID) FROM (SELECT * FROM network_flows Where original_label != 'BENIGN');

--SELECT * FROM import_batches order by id;

--SELECT SUM((features->>'bwd_urg_flags')::double precision) FROM network_flows;

--SELECT * FROM network_flows WHERE (features->>'ece_flag_count')::double precision != 0;


--SELECT * FROM network_flows WHERE (features->>'fwd_header_length_2')::NUMERIC != (features->>'fwd_header_length')::NUMERIC;

--SELECT features->>'avg_fwd_segment_size', features->>'fwd_packet_length_mean' FROM network_flows limit 1000;

