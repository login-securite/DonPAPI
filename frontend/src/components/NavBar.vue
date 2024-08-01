<template>
    <aside>
        <div class="navbar-title">
			<a href="https://github.com/login-securite/DonPAPI" target="_blank"><h1>DonPAPI</h1></a>
		</div>
        <div class="menu">
			<RouterLink to="/" class="button">
				<span class="text">General</span>
			</RouterLink>
            <RouterLink to="/cookies" class="button">
				<span class="text">Cookies</span>
			</RouterLink>
			<RouterLink to="/secrets" class="button">
				<span class="text">Secrets</span>
			</RouterLink>
			<RouterLink to="/certificates" class="button">
				<span class="text">Certificates</span>
			</RouterLink>
        </div>

		<div class="footer">
			<div class="logo">
            	<img alt="logo" class="logo" src="@/assets/logo_lse.png"/>
        	</div>
			<p>Powered by <a style="color: inherit;" target="_blank" href="https://www.login-securite.com">Login Sécurité</a></p>
		</div>
    </aside>
</template>

<style lang="scss" scoped>
aside {
	display: flex;
	flex-direction: column;

	background-color: var(--dark);
	color: var(--light);
	position:relative;
	width: var(--sidebar-width);
	min-height: 100vh;
	padding: 1rem;

	.navbar-title {
		a {
			text-decoration: none;
			color: #fff
		}

		a:hover {
			color: var(--primary);
		}
	}

	.flex {
		flex: 1 1 0%;
	}

	.logo {
		margin-bottom: 1rem;
		
	}

	.menu {
		margin: 0 -1rem;

		.button {
			display: flex;
			align-items: center;
			text-decoration: none;

			transition: 0.2s ease-in-out;
			padding: 0.5rem 1rem;

			.text {
				font-size: 1.3rem;
				color: var(--light);
				transition: 0.2s ease-in-out;
			}

			&:hover {
				background-color: var(--dark-alt);
			}

			&.router-link-exact-active {
				background-color: var(--dark-alt);
				border-right: 5px solid var(--primary);
			}
		}
	}

	.footer {
		// width: 5%;
		position: absolute;
  		bottom: 0;
		
		img {
			display: block;
			margin-left: auto;
			margin-right: auto;
			width: 10rem;
		}
		
		p {
			font-size: 0.875rem;
			color: var(--grey);
		}
	}
}
</style>