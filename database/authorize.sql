SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='TRADITIONAL';

CREATE SCHEMA IF NOT EXISTS `authorize` DEFAULT CHARACTER SET latin1 COLLATE latin1_swedish_ci ;
USE `authorize`;

-- -----------------------------------------------------
-- Table `authorize`.`users`
-- -----------------------------------------------------
CREATE  TABLE IF NOT EXISTS `authorize`.`users` (
  `userId` INT UNSIGNED NOT NULL AUTO_INCREMENT ,
  `username` VARCHAR(255) NOT NULL ,
  PRIMARY KEY (`userId`) ,
  INDEX `IDX_users_username` (`username` ASC) )
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `authorize`.`roles`
-- -----------------------------------------------------
CREATE  TABLE IF NOT EXISTS `authorize`.`roles` (
  `roleId` INT UNSIGNED NOT NULL AUTO_INCREMENT ,
  `rolename` VARCHAR(32) NOT NULL ,
  PRIMARY KEY (`roleId`) ,
  INDEX `IDX_roles_rolename` (`rolename` ASC) )
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `authorize`.`user_roles`
-- -----------------------------------------------------
CREATE  TABLE IF NOT EXISTS `authorize`.`user_roles` (
  `userId` INT UNSIGNED NOT NULL ,
  `roleId` INT UNSIGNED NOT NULL ,
  PRIMARY KEY (`userId`, `roleId`) ,
  INDEX `FK_user_roles_userId` (`userId` ASC) ,
  INDEX `FK_user_roles_roleId` (`roleId` ASC) ,
  CONSTRAINT `FK_user_roles_userId`
    FOREIGN KEY (`userId` )
    REFERENCES `authorize`.`users` (`userId` )
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  CONSTRAINT `FK_user_roles_roleId`
    FOREIGN KEY (`roleId` )
    REFERENCES `authorize`.`roles` (`roleId` )
    ON DELETE CASCADE
    ON UPDATE CASCADE)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `authorize`.`user_privs`
-- -----------------------------------------------------
CREATE  TABLE IF NOT EXISTS `authorize`.`user_privs` (
  `userId` INT UNSIGNED NOT NULL ,
  `privId` INT NOT NULL ,
  PRIMARY KEY (`userId`, `privId`) ,
  INDEX `FK_user_privs_userId` (`userId` ASC) ,
  INDEX `IDX_user_privs_privId` (`privId` ASC) ,
  CONSTRAINT `FK_user_privs_userId`
    FOREIGN KEY (`userId` )
    REFERENCES `authorize`.`users` (`userId` )
    ON DELETE CASCADE
    ON UPDATE CASCADE)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `authorize`.`role_privs`
-- -----------------------------------------------------
CREATE  TABLE IF NOT EXISTS `authorize`.`role_privs` (
  `roleId` INT UNSIGNED NOT NULL ,
  `privId` INT NOT NULL ,
  PRIMARY KEY (`roleId`, `privId`) ,
  INDEX `FK_role_privs_roleId` (`roleId` ASC) ,
  INDEX `IDX_role_privs_privId` (`privId` ASC) ,
  CONSTRAINT `FK_role_privs_roleId`
    FOREIGN KEY (`roleId` )
    REFERENCES `authorize`.`roles` (`roleId` )
    ON DELETE CASCADE
    ON UPDATE CASCADE)
ENGINE = InnoDB;



SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;
