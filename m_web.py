import web

urls = (
	'/', 'index'		
)

app = web.application(urls, globals())

class index:
	def GET(self):
		greeting = 'hello world'
		return greeting

if __name__ == '__main__':
	app.run()
