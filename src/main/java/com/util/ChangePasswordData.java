package com.util;

public class ChangePasswordData {
	public String oldPassword;
	public String newPassword;
	public String newPasswordConfirm;
	
	public ChangePasswordData() {};
	
	public ChangePasswordData(String oldPassword, String newPassword, String newPasswordConfirm) {
		this.oldPassword = oldPassword;
		this.newPassword = newPassword;
		this.newPasswordConfirm = newPasswordConfirm;
	}
}
