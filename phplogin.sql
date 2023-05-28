
CREATE TABLE `accounts` (
  `id` int NOT NULL,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `email` varchar(100) NOT NULL,
  `activation_code` varchar(50) DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;


CREATE TABLE `password` (
  `id` int NOT NULL,
  `URL` varchar(255) NOT NULL,
  `username` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `no` int NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


ALTER TABLE `accounts`
  ADD PRIMARY KEY (`id`);


ALTER TABLE `password`
  ADD PRIMARY KEY (`no`);



ALTER TABLE `accounts`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=129;


ALTER TABLE `password`
  MODIFY `no` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;
COMMIT;
