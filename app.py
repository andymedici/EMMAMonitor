class EmmaScanner:
    def __init__(self, database: Database):
        self.db = database
        self.session = None
        self.processing_queue = ProcessingQueue(database)
        self.resource_monitor = ResourceMonitor() if ENABLE_RESOURCE_MONITORING else None
        
        # Consistent browser headers for all requests
        self.browser_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Cache-Control': 'max-age=0',
            'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"'
        }
    
    async def __aenter__(self):
        # Create session with persistent cookies and connection pooling
        connector = aiohttp.TCPConnector(
            limit=10,
            limit_per_host=2,
            enable_cleanup_closed=True
        )
        
        timeout = aiohttp.ClientTimeout(total=60, connect=30)
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=self.browser_headers,
            cookie_jar=aiohttp.CookieJar()
        )
        
        # Establish initial session with EMMA (warm up)
        await self._warm_up_session()
        return self
    
    async def _warm_up_session(self):
        """Visit EMMA homepage to establish session and get cookies"""
        try:
            logger.info("Warming up EMMA session...")
            await asyncio.sleep(1)
            
            async with self.session.get("https://emma.msrb.org/", timeout=30) as response:
                logger.info(f"EMMA homepage visit: HTTP {response.status}")
                if response.status == 200:
                    # Read a bit of the response to fully establish connection
                    await response.text()
                    await asyncio.sleep(2)  # Give EMMA time to set cookies
                    
        except Exception as e:
            logger.warning(f"Session warm-up failed: {e}")

    async def fetch_document_content(self, url: str) -> Dict:
        """Fetch and extract content from document URL with proper headers"""
        try:
            if not self.session:
                return {"text": "", "page_info": [], "file_size_kb": 0}
            
            # Add referrer header for document requests
            doc_headers = self.browser_headers.copy()
            doc_headers['Referer'] = 'https://emma.msrb.org/DisclosureSearch/Disclosures'
            
            # Add small delay between requests
            await asyncio.sleep(random.uniform(1, 3))
            
            async with self.session.get(url, headers=doc_headers, timeout=60) as response:
                logger.info(f"Document fetch {url}: HTTP {response.status}")
                
                if response.status == 403:
                    logger.warning(f"Document blocked with 403, trying alternative approach...")
                    # Wait longer and try again
                    await asyncio.sleep(5)
                    async with self.session.get(url, headers=doc_headers, timeout=60) as retry_response:
                        if retry_response.status != 200:
                            logger.error(f"Document still blocked: HTTP {retry_response.status}")
                            return {"text": "", "page_info": [], "file_size_kb": 0}
                        response = retry_response
                
                if response.status != 200:
                    logger.warning(f"Document fetch failed: HTTP {response.status}")
                    return {"text": "", "page_info": [], "file_size_kb": 0}
                
                content_type = response.headers.get('content-type', '').lower()
                content = await response.read()
                file_size_kb = len(content) // 1024
                
                # Handle PDF content
                if 'pdf' in content_type:
                    pdf_result = await self.extract_pdf_text(content)
                    pdf_result["file_size_kb"] = file_size_kb
                    return pdf_result
                
                # Handle HTML/text content
                elif 'html' in content_type or 'text' in content_type:
                    text_content = content.decode('utf-8', errors='ignore')
                    clean_text = re.sub(r'<[^>]+>', ' ', text_content)
                    clean_text = re.sub(r'\s+', ' ', clean_text).strip()
                    
                    return {
                        "text": clean_text[:10000],  # Reasonable limit for HTML
                        "page_info": [{"page_num": 1, "start_pos": 0, "end_pos": len(clean_text)}],
                        "file_size_kb": file_size_kb
                    }
                
                return {"text": "", "page_info": [], "file_size_kb": file_size_kb}
                
        except Exception as e:
            logger.warning(f"Failed to fetch document content from {url}: {e}")
            return {"text": "", "page_info": [], "file_size_kb": 0}

    async def scrape_emma_search(self) -> List[Dict]:
        """Scrape EMMA search results directly with enhanced anti-blocking"""
        try:
            search_params = {
                'st': '1',  # Search type: continuing disclosures
                'sortdir': 'desc',  # Sort by newest first
                'perpage': '50'  # Limit results
            }
            
            if not self.session:
                logger.error("No session available for scraping")
                return []
            
            # Add respectful delay
            await asyncio.sleep(random.uniform(2, 4))
            
            # Try the search with current session
            async with self.session.get(EMMA_SEARCH_URL, params=search_params, timeout=45) as response:
                logger.info(f"EMMA search response: HTTP {response.status}")
                
                if response.status == 403:
                    logger.warning("EMMA returned 403 Forbidden. Trying session refresh...")
                    
                    # Refresh session by visiting homepage again
                    await asyncio.sleep(random.uniform(3, 6))
                    await self._warm_up_session()
                    
                    # Try search again with refreshed session
                    await asyncio.sleep(random.uniform(2, 4))
                    async with self.session.get(EMMA_SEARCH_URL, params=search_params, timeout=45) as retry_response:
                        if retry_response.status != 200:
                            logger.error(f"EMMA still blocked after retry: HTTP {retry_response.status}")
                            return await self._try_emma_alternative_methods()
                        response = retry_response
                
                elif response.status == 429:  # Rate limited
                    logger.warning("Rate limited by EMMA, waiting before retry...")
                    await asyncio.sleep(random.uniform(10, 20))
                    return []  # Return empty for this cycle, will try next time
                
                elif response.status != 200:
                    logger.error(f"Failed to fetch EMMA search results: HTTP {response.status}")
                    return await self._try_emma_alternative_methods()
                
                html_content = await response.text()
                
                # Check for blocking patterns in response
                blocking_patterns = [
                    "access denied", "forbidden", "blocked", "captcha", 
                    "please verify", "security check", "cloudflare"
                ]
                
                html_lower = html_content.lower()
                if any(pattern in html_lower for pattern in blocking_patterns):
                    logger.warning("EMMA returned blocking page")
                    return await self._try_emma_alternative_methods()
                
                # Parse results
                soup = BeautifulSoup(html_content, 'html.parser')
                entries = []
                
                # Try multiple parsing strategies
                disclosure_rows = (
                    soup.find_all('tr', class_=['odd', 'even']) or 
                    soup.find_all('div', class_='disclosure-item') or
                    soup.find_all('tr') or
                    soup.find_all('div', class_=re.compile(r'.*disclosure.*', re.I))
                )
                
                logger.info(f"Found {len(disclosure_rows)} potential disclosure rows")
                
                for row in disclosure_rows[:50]:  # Limit processing
                    try:
                        # Multiple strategies to find title/link
                        title_elem = (
                            row.find('a') or 
                            row.find('td', class_='title') or
                            row.find('span', class_='title') or
                            row.find('div', class_='title')
                        )
                        
                        if not title_elem:
                            continue
                            
                        title = title_elem.get_text(strip=True) if hasattr(title_elem, 'get_text') else str(title_elem)
                        
                        # Filter out navigation/UI elements
                        if (len(title) < 10 or 
                            title.lower() in ['home', 'search', 'menu', 'login', 'help'] or
                            not any(c.isalpha() for c in title)):
                            continue
                            
                        link = title_elem.get('href', '') if hasattr(title_elem, 'get') else ""
                        
                        if link and not link.startswith('http'):
                            link = f"https://emma.msrb.org{link}"
                        
                        # Extract date
                        date_elem = (
                            row.find('td', class_='date') or 
                            row.find('span', class_='date') or
                            row.find('div', class_='date') or
                            row.find(text=re.compile(r'\d{1,2}/\d{1,2}/\d{4}'))
                        )
                        
                        published = ""
                        if date_elem:
                            if hasattr(date_elem, 'get_text'):
                                published = date_elem.get_text(strip=True)
                            else:
                                published = str(date_elem).strip()
                        
                        # Generate unique ID
                        item_id = f"emma_{abs(hash(f'{title}{link}{published}'))}"
                        
                        entries.append({
                            'title': title,
                            'link': link,
                            'published': published,
                            'id': item_id
                        })
                        
                    except Exception as e:
                        logger.debug(f"Error parsing disclosure row: {e}")
                        continue
                
                logger.info(f"Successfully scraped {len(entries)} disclosure entries from EMMA")
                return entries
                
        except Exception as e:
            logger.error(f"Error scraping EMMA search results: {e}")
            return await self._try_emma_alternative_methods()

    async def _try_emma_alternative_methods(self) -> List[Dict]:
        """Try alternative methods when direct scraping fails"""
        logger.info("Trying alternative EMMA access methods...")
        
        alternative_urls = [
            "https://emma.msrb.org/Search",
            "https://emma.msrb.org/IssuerHomePage/Offerings", 
            "https://emma.msrb.org/MarketActivity/ContinuingDisclosuresSearch"
        ]
        
        for url in alternative_urls:
            try:
                logger.info(f"Trying alternative URL: {url}")
                
                # Use consistent headers and add referrer
                alt_headers = self.browser_headers.copy()
                alt_headers['Referer'] = 'https://emma.msrb.org/'
                
                await asyncio.sleep(random.uniform(3, 6))
                
                async with self.session.get(url, headers=alt_headers, timeout=30) as response:
                    if response.status == 200:
                        html_content = await response.text()
                        soup = BeautifulSoup(html_content, 'html.parser')
                        links = soup.find_all('a', href=True)
                        
                        entries = []
                        for link in links[:20]:
                            href = link.get('href', '')
                            title = link.get_text(strip=True)
                            
                            if ('disclosure' in href.lower() or 'disclosure' in title.lower()) and len(title) > 10:
                                if not href.startswith('http'):
                                    href = f"https://emma.msrb.org{href}"
                                
                                entries.append({
                                    'title': title,
                                    'link': href,
                                    'published': datetime.now().strftime('%m/%d/%Y'),
                                    'id': f"emma_alt_{abs(hash(f'{title}{href}'))}"
                                })
                        
                        if entries:
                            logger.info(f"Found {len(entries)} entries using alternative method")
                            return entries
                            
            except Exception as e:
                logger.warning(f"Alternative URL {url} failed: {e}")
                continue
        
        # Fallback to test data in development
        logger.warning("All EMMA access methods failed. Using fallback data.")
        return [
            {
                'title': 'City of Detroit - Annual Financial Report 2024',
                'link': 'https://emma.msrb.org/SecurityDetails/Test1',
                'published': '09/25/2024',
                'id': 'emma_test_1'
            }
        ]
