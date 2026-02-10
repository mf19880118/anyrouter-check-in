#!/usr/bin/env python3
"""
AnyRouter.top 自动签到脚本 (Enhanced with Auto-Login)

改造说明：
- 原有逻辑完全保留
- 新增自动登录功能：当 Session/api_user 过期时，
  通过 Playwright 模拟登录获取新的凭证，实现长期自动签到
- 新增环境变量：ANYROUTER_USERNAME, ANYROUTER_PASSWORD
"""

import asyncio
import hashlib
import json
import os
import sys
from datetime import datetime

import httpx
from dotenv import load_dotenv
from playwright.async_api import async_playwright

from utils.config import AccountConfig, AppConfig, load_accounts_config
from utils.notify import notify

load_dotenv()

BALANCE_HASH_FILE = 'balance_hash.txt'


def load_balance_hash():
	"""加载余额hash"""
	try:
		if os.path.exists(BALANCE_HASH_FILE):
			with open(BALANCE_HASH_FILE, 'r', encoding='utf-8') as f:
				return f.read().strip()
	except Exception:
		pass
	return None


def save_balance_hash(balance_hash):
	"""保存余额hash"""
	try:
		with open(BALANCE_HASH_FILE, 'w', encoding='utf-8') as f:
			f.write(balance_hash)
	except Exception as e:
		print(f'Warning: Failed to save balance hash: {e}')


def generate_balance_hash(balances):
	"""生成余额数据的hash"""
	simple_balances = {k: v['quota'] for k, v in balances.items()} if balances else {}
	balance_json = json.dumps(simple_balances, sort_keys=True, separators=(',', ':'))
	return hashlib.sha256(balance_json.encode('utf-8')).hexdigest()[:16]


def parse_cookies(cookies_data):
	"""解析 cookies 数据"""
	if isinstance(cookies_data, dict):
		return cookies_data

	if isinstance(cookies_data, str):
		cookies_dict = {}
		for cookie in cookies_data.split(';'):
			if '=' in cookie:
				key, value = cookie.strip().split('=', 1)
				cookies_dict[key] = value
		return cookies_dict
	return {}


async def auto_login_and_get_credentials(account_name: str, provider_config, username: str, password: str):
	"""
	使用 Playwright 自动登录 AnyRouter，获取新的 session cookie 和 api_user ID。

	Returns:
		dict | None: {'session': str, 'api_user': str, 'waf_cookies': dict} or None on failure
	"""
	login_url = f'{provider_config.domain}{provider_config.login_path}'
	print(f'[AUTO-LOGIN] {account_name}: Starting automatic login to {provider_config.domain}...')

	async with async_playwright() as p:
		import tempfile

		with tempfile.TemporaryDirectory() as temp_dir:
			context = await p.chromium.launch_persistent_context(
				user_data_dir=temp_dir,
				headless=False,
				user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
				viewport={'width': 1920, 'height': 1080},
				args=[
					'--disable-blink-features=AutomationControlled',
					'--disable-dev-shm-usage',
					'--disable-web-security',
					'--disable-features=VizDisplayCompositor',
					'--no-sandbox',
				],
			)

			page = await context.new_page()

			try:
				# Step 1: Navigate to login page and wait for WAF
				print(f'[AUTO-LOGIN] {account_name}: Navigating to login page...')
				await page.goto(login_url, wait_until='networkidle')

				try:
					await page.wait_for_function('document.readyState === "complete"', timeout=10000)
				except Exception:
					await page.wait_for_timeout(5000)

				# Step 2: Wait for login form to appear
				print(f'[AUTO-LOGIN] {account_name}: Waiting for login form...')

				# Try multiple possible selectors for the username/email input
				username_selector = None
				possible_username_selectors = [
					'input[name="username"]',
					'input[name="email"]',
					'input[type="text"]',
					'input[type="email"]',
					'input[id="username"]',
					'input[id="email"]',
					'input[placeholder*="用户名"]',
					'input[placeholder*="邮箱"]',
					'input[placeholder*="username"]',
					'input[placeholder*="email"]',
				]

				for selector in possible_username_selectors:
					try:
						element = await page.wait_for_selector(selector, timeout=3000)
						if element and await element.is_visible():
							username_selector = selector
							print(f'[AUTO-LOGIN] {account_name}: Found username input: {selector}')
							break
					except Exception:
						continue

				if not username_selector:
					print(f'[AUTO-LOGIN] {account_name}: Could not find username input field')
					# Take a screenshot for debugging
					try:
						screenshot_path = f'login_debug_{account_name}.png'
						await page.screenshot(path=screenshot_path)
						print(f'[AUTO-LOGIN] {account_name}: Debug screenshot saved to {screenshot_path}')
					except Exception:
						pass
					await context.close()
					return None

				# Step 3: Find password input
				password_selector = None
				possible_password_selectors = [
					'input[name="password"]',
					'input[type="password"]',
					'input[id="password"]',
					'input[placeholder*="密码"]',
					'input[placeholder*="password"]',
				]

				for selector in possible_password_selectors:
					try:
						element = await page.wait_for_selector(selector, timeout=3000)
						if element and await element.is_visible():
							password_selector = selector
							print(f'[AUTO-LOGIN] {account_name}: Found password input: {selector}')
							break
					except Exception:
						continue

				if not password_selector:
					print(f'[AUTO-LOGIN] {account_name}: Could not find password input field')
					await context.close()
					return None

				# Step 4: Fill in credentials
				print(f'[AUTO-LOGIN] {account_name}: Filling in credentials...')
				await page.fill(username_selector, username)
				await page.wait_for_timeout(500)
				await page.fill(password_selector, password)
				await page.wait_for_timeout(500)

				# Step 5: Click login button
				login_button_selector = None
				possible_button_selectors = [
					'button[type="submit"]',
					'button:has-text("登录")',
					'button:has-text("Login")',
					'button:has-text("Sign in")',
					'button:has-text("登 录")',
					'input[type="submit"]',
					'.login-btn',
					'#login-btn',
				]

				for selector in possible_button_selectors:
					try:
						element = await page.wait_for_selector(selector, timeout=2000)
						if element and await element.is_visible():
							login_button_selector = selector
							print(f'[AUTO-LOGIN] {account_name}: Found login button: {selector}')
							break
					except Exception:
						continue

				if not login_button_selector:
					# Fallback: try pressing Enter
					print(f'[AUTO-LOGIN] {account_name}: No login button found, pressing Enter...')
					await page.press(password_selector, 'Enter')
				else:
					await page.click(login_button_selector)

				# Step 6: Wait for login to complete (page navigation or URL change)
				print(f'[AUTO-LOGIN] {account_name}: Waiting for login response...')
				try:
					await page.wait_for_url(
						lambda url: '/login' not in url,
						timeout=15000,
					)
					print(f'[AUTO-LOGIN] {account_name}: Login navigation detected, current URL: {page.url}')
				except Exception:
					# URL might not change, check for error messages
					current_url = page.url
					print(f'[AUTO-LOGIN] {account_name}: URL after login attempt: {current_url}')

					# Check for error messages on page
					try:
						error_elements = await page.query_selector_all('.error, .alert-danger, .ant-message-error, .el-message--error')
						for el in error_elements:
							error_text = await el.text_content()
							if error_text and error_text.strip():
								print(f'[AUTO-LOGIN] {account_name}: Login error detected: {error_text.strip()}')
								await context.close()
								return None
					except Exception:
						pass

				# Step 7: Wait a moment for cookies to settle
				await page.wait_for_timeout(3000)

				# Step 8: Extract cookies from browser
				all_browser_cookies = await page.context.cookies()

				session_value = None
				waf_cookies = {}

				for cookie in all_browser_cookies:
					cookie_name = cookie.get('name', '')
					cookie_value = cookie.get('value', '')

					if cookie_name == 'session':
						session_value = cookie_value
					elif provider_config.waf_cookie_names and cookie_name in provider_config.waf_cookie_names:
						waf_cookies[cookie_name] = cookie_value

				if not session_value:
					print(f'[AUTO-LOGIN] {account_name}: No session cookie found after login')
					# Print all cookies for debugging
					cookie_names = [c.get('name', '?') for c in all_browser_cookies]
					print(f'[AUTO-LOGIN] {account_name}: Available cookies: {cookie_names}')
					try:
						screenshot_path = f'login_debug_{account_name}.png'
						await page.screenshot(path=screenshot_path)
						print(f'[AUTO-LOGIN] {account_name}: Debug screenshot saved to {screenshot_path}')
					except Exception:
						pass
					await context.close()
					return None

				print(f'[AUTO-LOGIN] {account_name}: Session cookie obtained: {session_value[:8]}...')
				print(f'[AUTO-LOGIN] {account_name}: WAF cookies obtained: {list(waf_cookies.keys())}')

				# Step 9: Get api_user (user ID) via API call
				api_user = None
				user_info_url = f'{provider_config.domain}{provider_config.user_info_path}'

				try:
					# Use the browser to make the API call (already authenticated)
					api_response = await page.evaluate(f'''
						async () => {{
							const response = await fetch("{user_info_url}");
							const data = await response.json();
							return data;
						}}
					''')

					if api_response and api_response.get('success'):
						user_data = api_response.get('data', {})
						api_user = str(user_data.get('id', ''))
						if api_user:
							print(f'[AUTO-LOGIN] {account_name}: API user ID obtained: {api_user}')
						else:
							print(f'[AUTO-LOGIN] {account_name}: User data found but no ID field')
					else:
						print(f'[AUTO-LOGIN] {account_name}: API response not successful: {api_response}')
				except Exception as e:
					print(f'[AUTO-LOGIN] {account_name}: Failed to get api_user via browser API: {e}')

				# If we couldn't get api_user from API, try extracting from cookie
				if not api_user:
					for cookie in all_browser_cookies:
						if cookie.get('name', '') == 'new-api-user':
							api_user = cookie.get('value', '')
							if api_user:
								print(f'[AUTO-LOGIN] {account_name}: API user obtained from cookie: {api_user}')
								break

				if not api_user:
					print(f'[AUTO-LOGIN] {account_name}: WARNING - Could not obtain api_user, login may be incomplete')
					await context.close()
					return None

				await context.close()

				print(f'[AUTO-LOGIN] {account_name}: Auto-login completed successfully!')
				return {
					'session': session_value,
					'api_user': api_user,
					'waf_cookies': waf_cookies,
				}

			except Exception as e:
				print(f'[AUTO-LOGIN] {account_name}: Error during auto-login: {e}')
				try:
					screenshot_path = f'login_debug_{account_name}.png'
					await page.screenshot(path=screenshot_path)
					print(f'[AUTO-LOGIN] {account_name}: Debug screenshot saved to {screenshot_path}')
				except Exception:
					pass
				await context.close()
				return None


async def get_waf_cookies_with_playwright(account_name: str, login_url: str, required_cookies: list[str]):
	"""使用 Playwright 获取 WAF cookies（隐私模式）"""
	print(f'[PROCESSING] {account_name}: Starting browser to get WAF cookies...')

	async with async_playwright() as p:
		import tempfile

		with tempfile.TemporaryDirectory() as temp_dir:
			context = await p.chromium.launch_persistent_context(
				user_data_dir=temp_dir,
				headless=False,
				user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
				viewport={'width': 1920, 'height': 1080},
				args=[
					'--disable-blink-features=AutomationControlled',
					'--disable-dev-shm-usage',
					'--disable-web-security',
					'--disable-features=VizDisplayCompositor',
					'--no-sandbox',
				],
			)

			page = await context.new_page()

			try:
				print(f'[PROCESSING] {account_name}: Access login page to get initial cookies...')

				await page.goto(login_url, wait_until='networkidle')

				try:
					await page.wait_for_function('document.readyState === "complete"', timeout=5000)
				except Exception:
					await page.wait_for_timeout(3000)

				cookies = await page.context.cookies()

				waf_cookies = {}
				for cookie in cookies:
					cookie_name = cookie.get('name')
					cookie_value = cookie.get('value')
					if cookie_name in required_cookies and cookie_value is not None:
						waf_cookies[cookie_name] = cookie_value

				print(f'[INFO] {account_name}: Got {len(waf_cookies)} WAF cookies')

				missing_cookies = [c for c in required_cookies if c not in waf_cookies]

				if missing_cookies:
					print(f'[FAILED] {account_name}: Missing WAF cookies: {missing_cookies}')
					await context.close()
					return None

				print(f'[SUCCESS] {account_name}: Successfully got all WAF cookies')

				await context.close()

				return waf_cookies

			except Exception as e:
				print(f'[FAILED] {account_name}: Error occurred while getting WAF cookies: {e}')
				await context.close()
				return None


def get_user_info(client, headers, user_info_url: str):
	"""获取用户信息"""
	try:
		response = client.get(user_info_url, headers=headers, timeout=30)

		if response.status_code == 200:
			data = response.json()
			if data.get('success'):
				user_data = data.get('data', {})
				quota = round(user_data.get('quota', 0) / 500000, 2)
				used_quota = round(user_data.get('used_quota', 0) / 500000, 2)
				return {
					'success': True,
					'quota': quota,
					'used_quota': used_quota,
					'display': f':money: Current balance: ${quota}, Used: ${used_quota}',
				}
		return {'success': False, 'error': f'Failed to get user info: HTTP {response.status_code}'}
	except Exception as e:
		return {'success': False, 'error': f'Failed to get user info: {str(e)[:50]}...'}


async def prepare_cookies(account_name: str, provider_config, user_cookies: dict) -> dict | None:
	"""准备请求所需的 cookies（可能包含 WAF cookies）"""
	waf_cookies = {}

	if provider_config.needs_waf_cookies():
		login_url = f'{provider_config.domain}{provider_config.login_path}'
		waf_cookies = await get_waf_cookies_with_playwright(account_name, login_url, provider_config.waf_cookie_names)
		if not waf_cookies:
			print(f'[FAILED] {account_name}: Unable to get WAF cookies')
			return None
	else:
		print(f'[INFO] {account_name}: Bypass WAF not required, using user cookies directly')

	return {**waf_cookies, **user_cookies}


def execute_check_in(client, account_name: str, provider_config, headers: dict):
	"""执行签到请求"""
	print(f'[NETWORK] {account_name}: Executing check-in')

	checkin_headers = headers.copy()
	checkin_headers.update({'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'})

	sign_in_url = f'{provider_config.domain}{provider_config.sign_in_path}'
	response = client.post(sign_in_url, headers=checkin_headers, timeout=30)

	print(f'[RESPONSE] {account_name}: Response status code {response.status_code}')

	if response.status_code == 200:
		try:
			result = response.json()
			if result.get('ret') == 1 or result.get('code') == 0 or result.get('success'):
				print(f'[SUCCESS] {account_name}: Check-in successful!')
				return True
			else:
				error_msg = result.get('msg', result.get('message', 'Unknown error'))
				print(f'[FAILED] {account_name}: Check-in failed - {error_msg}')
				return False
		except json.JSONDecodeError:
			if 'success' in response.text.lower():
				print(f'[SUCCESS] {account_name}: Check-in successful!')
				return True
			else:
				print(f'[FAILED] {account_name}: Check-in failed - Invalid response format')
				return False
	else:
		print(f'[FAILED] {account_name}: Check-in failed - HTTP {response.status_code}')
		return False


def is_session_expired(user_info: dict | None, response_status: int = 200) -> bool:
	"""判断 Session 是否已过期"""
	if response_status in (401, 403):
		return True
	if user_info and not user_info.get('success'):
		error_msg = user_info.get('error', '')
		# Common indicators of expired session
		if any(keyword in error_msg.lower() for keyword in ['401', '403', 'unauthorized', 'login', 'expired', 'invalid']):
			return True
		# HTTP error status in the error message
		if 'HTTP 401' in error_msg or 'HTTP 403' in error_msg:
			return True
	return False


async def try_checkin_with_auto_login(account: AccountConfig, account_name: str, provider_config, app_config: AppConfig):
	"""
	尝试签到，如果 Session 过期则自动登录获取新凭证后重试。

	Returns:
		(success: bool, user_info: dict | None)
	"""
	# --- First attempt: use existing credentials ---
	user_cookies = parse_cookies(account.cookies)
	if not user_cookies:
		print(f'[FAILED] {account_name}: Invalid configuration format')
		return False, None

	all_cookies = await prepare_cookies(account_name, provider_config, user_cookies)
	if not all_cookies:
		return False, None

	client = httpx.Client(http2=True, timeout=30.0)

	try:
		client.cookies.update(all_cookies)

		headers = {
			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
			'Accept': 'application/json, text/plain, */*',
			'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
			'Accept-Encoding': 'gzip, deflate, br, zstd',
			'Referer': provider_config.domain,
			'Origin': provider_config.domain,
			'Connection': 'keep-alive',
			'Sec-Fetch-Dest': 'empty',
			'Sec-Fetch-Mode': 'cors',
			'Sec-Fetch-Site': 'same-origin',
			provider_config.api_user_key: account.api_user,
		}

		user_info_url = f'{provider_config.domain}{provider_config.user_info_path}'
		user_info = get_user_info(client, headers, user_info_url)

		if user_info and user_info.get('success'):
			print(user_info['display'])

			# Existing session is valid, proceed with check-in
			if provider_config.needs_manual_check_in():
				success = execute_check_in(client, account_name, provider_config, headers)
				return success, user_info
			else:
				print(f'[INFO] {account_name}: Check-in completed automatically (triggered by user info request)')
				return True, user_info

		# --- Session might be expired, check if we should auto-login ---
		print(f'[WARNING] {account_name}: Existing credentials failed - {user_info.get("error", "unknown")}')

	except Exception as e:
		print(f'[WARNING] {account_name}: Error with existing credentials: {str(e)[:80]}')
		user_info = None
	finally:
		client.close()

	# --- Second attempt: auto-login and retry ---
	username = os.getenv('ANYROUTER_USERNAME', '').strip()
	password = os.getenv('ANYROUTER_PASSWORD', '').strip()

	if not username or not password:
		print(f'[FAILED] {account_name}: Session expired but ANYROUTER_USERNAME/ANYROUTER_PASSWORD not configured')
		print(f'[INFO] {account_name}: To enable auto-login, set these environment variables in GitHub Secrets')
		return False, user_info

	print(f'[AUTO-LOGIN] {account_name}: Attempting automatic re-login...')

	login_result = await auto_login_and_get_credentials(account_name, provider_config, username, password)

	if not login_result:
		print(f'[FAILED] {account_name}: Auto-login failed, unable to recover session')
		return False, user_info

	# Use fresh credentials
	new_session = login_result['session']
	new_api_user = login_result['api_user']
	new_waf_cookies = login_result.get('waf_cookies', {})

	print(f'[AUTO-LOGIN] {account_name}: Retrying check-in with fresh credentials...')

	client2 = httpx.Client(http2=True, timeout=30.0)
	try:
		# Merge new WAF cookies with new session
		fresh_cookies = {**new_waf_cookies, 'session': new_session}
		client2.cookies.update(fresh_cookies)

		headers2 = {
			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
			'Accept': 'application/json, text/plain, */*',
			'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
			'Accept-Encoding': 'gzip, deflate, br, zstd',
			'Referer': provider_config.domain,
			'Origin': provider_config.domain,
			'Connection': 'keep-alive',
			'Sec-Fetch-Dest': 'empty',
			'Sec-Fetch-Mode': 'cors',
			'Sec-Fetch-Site': 'same-origin',
			provider_config.api_user_key: new_api_user,
		}

		user_info_url = f'{provider_config.domain}{provider_config.user_info_path}'
		user_info2 = get_user_info(client2, headers2, user_info_url)

		if user_info2 and user_info2.get('success'):
			print(f'[AUTO-LOGIN] {account_name}: Fresh credentials validated! {user_info2["display"]}')

			if provider_config.needs_manual_check_in():
				success = execute_check_in(client2, account_name, provider_config, headers2)
				return success, user_info2
			else:
				print(f'[INFO] {account_name}: Check-in completed automatically (triggered by user info request)')
				return True, user_info2
		else:
			print(f'[FAILED] {account_name}: Even fresh credentials failed - {user_info2}')
			return False, user_info2

	except Exception as e:
		print(f'[FAILED] {account_name}: Error with fresh credentials: {str(e)[:80]}')
		return False, None
	finally:
		client2.close()


async def check_in_account(account: AccountConfig, account_index: int, app_config: AppConfig):
	"""为单个账号执行签到操作（支持自动登录重试）"""
	account_name = account.get_display_name(account_index)
	print(f'\n[PROCESSING] Starting to process {account_name}')

	provider_config = app_config.get_provider(account.provider)
	if not provider_config:
		print(f'[FAILED] {account_name}: Provider "{account.provider}" not found in configuration')
		return False, None

	print(f'[INFO] {account_name}: Using provider "{account.provider}" ({provider_config.domain})')

	# Use the enhanced flow with auto-login capability
	return await try_checkin_with_auto_login(account, account_name, provider_config, app_config)


async def main():
	"""主函数"""
	print('[SYSTEM] AnyRouter.top multi-account auto check-in script started (Enhanced with Auto-Login)')
	print(f'[TIME] Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')

	# Check if auto-login credentials are available
	has_login_creds = bool(os.getenv('ANYROUTER_USERNAME', '').strip() and os.getenv('ANYROUTER_PASSWORD', '').strip())
	if has_login_creds:
		print('[INFO] Auto-login credentials detected, session recovery enabled')
	else:
		print('[INFO] No auto-login credentials configured, session recovery disabled')

	app_config = AppConfig.load_from_env()
	print(f'[INFO] Loaded {len(app_config.providers)} provider configuration(s)')

	accounts = load_accounts_config()
	if not accounts:
		print('[FAILED] Unable to load account configuration, program exits')
		sys.exit(1)

	print(f'[INFO] Found {len(accounts)} account configurations')

	last_balance_hash = load_balance_hash()

	success_count = 0
	total_count = len(accounts)
	notification_content = []
	current_balances = {}
	need_notify = False
	balance_changed = False

	for i, account in enumerate(accounts):
		account_key = f'account_{i + 1}'
		try:
			success, user_info = await check_in_account(account, i, app_config)
			if success:
				success_count += 1

			should_notify_this_account = False

			if not success:
				should_notify_this_account = True
				need_notify = True
				account_name = account.get_display_name(i)
				print(f'[NOTIFY] {account_name} failed, will send notification')

			if user_info and user_info.get('success'):
				current_quota = user_info['quota']
				current_used = user_info['used_quota']
				current_balances[account_key] = {'quota': current_quota, 'used': current_used}

			if should_notify_this_account:
				account_name = account.get_display_name(i)
				status = '[SUCCESS]' if success else '[FAIL]'
				account_result = f'{status} {account_name}'
				if user_info and user_info.get('success'):
					account_result += f'\n{user_info["display"]}'
				elif user_info:
					account_result += f'\n{user_info.get("error", "Unknown error")}'
				notification_content.append(account_result)

		except Exception as e:
			account_name = account.get_display_name(i)
			print(f'[FAILED] {account_name} processing exception: {e}')
			need_notify = True
			notification_content.append(f'[FAIL] {account_name} exception: {str(e)[:50]}...')

	# 检查余额变化
	current_balance_hash = generate_balance_hash(current_balances) if current_balances else None
	if current_balance_hash:
		if last_balance_hash is None:
			balance_changed = True
			need_notify = True
			print('[NOTIFY] First run detected, will send notification with current balances')
		elif current_balance_hash != last_balance_hash:
			balance_changed = True
			need_notify = True
			print('[NOTIFY] Balance changes detected, will send notification')
		else:
			print('[INFO] No balance changes detected')

	# 为有余额变化的情况添加所有成功账号到通知内容
	if balance_changed:
		for i, account in enumerate(accounts):
			account_key = f'account_{i + 1}'
			if account_key in current_balances:
				account_name = account.get_display_name(i)
				account_result = f'[BALANCE] {account_name}'
				account_result += f'\n:money: Current balance: ${current_balances[account_key]["quota"]}, Used: ${current_balances[account_key]["used"]}'
				# 检查是否已经在通知内容中（避免重复）
				if not any(account_name in item for item in notification_content):
					notification_content.append(account_result)

	# 保存当前余额hash
	if current_balance_hash:
		save_balance_hash(current_balance_hash)

	if need_notify and notification_content:
		# 构建通知内容
		summary = [
			'[STATS] Check-in result statistics:',
			f'[SUCCESS] Success: {success_count}/{total_count}',
			f'[FAIL] Failed: {total_count - success_count}/{total_count}',
		]

		if success_count == total_count:
			summary.append('[SUCCESS] All accounts check-in successful!')
		elif success_count > 0:
			summary.append('[WARN] Some accounts check-in successful')
		else:
			summary.append('[ERROR] All accounts check-in failed')

		time_info = f'[TIME] Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'

		notify_content = '\n\n'.join([time_info, '\n'.join(notification_content), '\n'.join(summary)])

		print(notify_content)
		notify.push_message('AnyRouter Check-in Alert', notify_content, msg_type='text')
		print('[NOTIFY] Notification sent due to failures or balance changes')
	else:
		print('[INFO] All accounts successful and no balance changes detected, notification skipped')

	# 设置退出码
	sys.exit(0 if success_count > 0 else 1)


def run_main():
	"""运行主函数的包装函数"""
	try:
		asyncio.run(main())
	except KeyboardInterrupt:
		print('\n[WARNING] Program interrupted by user')
		sys.exit(1)
	except Exception as e:
		print(f'\n[FAILED] Error occurred during program execution: {e}')
		sys.exit(1)


if __name__ == '__main__':
	run_main()